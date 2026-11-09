"""Read a `docker save` tar and rebuild the image filesystem on disk.

A saved image is a tar that contains:
  - manifest.json : which config file and which layer tars make up the image
  - a config JSON : image metadata, including the build history
  - layer tars    : one per filesystem-changing Dockerfile instruction

Each layer is a filesystem *diff*. To get the final filesystem we extract
the layers in order, letting later layers overwrite earlier ones, and we
honour "whiteout" files, which is how a layer records a deletion.
"""

import json
import os
import shutil
import tarfile
from pathlib import Path

# Package database paths we want to capture from every layer, so we can
# later work out which layer installed which package.
PACKAGE_DB_PATHS = ["var/lib/dpkg/status", "lib/apk/db/installed"]

WHITEOUT_PREFIX = ".wh."
OPAQUE_WHITEOUT = ".wh..wh..opq"


class ImageError(Exception):
    """Raised when the image tar is missing or not in the expected format."""


def read_json_member(image_tar: tarfile.TarFile, name: str) -> dict | list:
    """Read and parse one JSON file from inside the image tar."""
    try:
        member_file = image_tar.extractfile(name)
    except KeyError:
        raise ImageError(f"'{name}' not found inside the image tar")
    if member_file is None:
        raise ImageError(f"'{name}' inside the image tar is not a regular file")

    try:
        return json.load(member_file)
    except json.JSONDecodeError as error:
        raise ImageError(f"'{name}' is not valid JSON: {error}")


def read_manifest(image_tar: tarfile.TarFile) -> dict:
    """Return the first entry of manifest.json (one entry per saved image)."""
    manifest = read_json_member(image_tar, "manifest.json")
    if not isinstance(manifest, list) or len(manifest) == 0:
        raise ImageError("manifest.json is empty or not a list")

    entry = manifest[0]
    if "Config" not in entry or "Layers" not in entry:
        raise ImageError("manifest.json entry is missing 'Config' or 'Layers'")
    return entry


def clean_instruction(created_by: str) -> str:
    """Turn a history 'created_by' string into a readable Dockerfile line.

    The legacy builder records instructions as '/bin/sh -c #(nop) CMD ...'
    and RUN steps as '/bin/sh -c apt-get ...'. BuildKit appends
    ' # buildkit'. We strip that noise so the instruction reads naturally.
    """
    text = created_by.strip()

    if text.endswith("# buildkit"):
        text = text[: -len("# buildkit")].strip()

    nop_prefix = "/bin/sh -c #(nop)"
    legacy_run_prefix = "/bin/sh -c "
    buildkit_run_prefix = "RUN /bin/sh -c "
    if text.startswith(nop_prefix):
        text = text[len(nop_prefix):].strip()
    elif text.startswith(legacy_run_prefix):
        text = "RUN " + text[len(legacy_run_prefix):].strip()
    elif text.startswith(buildkit_run_prefix):
        text = "RUN " + text[len(buildkit_run_prefix):].strip()

    # Collapse newlines, tabs and repeated spaces into single spaces.
    return " ".join(text.split())


def match_history_to_layers(history: list[dict], layer_count: int) -> list[str]:
    """Pair each layer with the Dockerfile instruction that created it.

    The history has one entry per instruction, but instructions such as
    ENV or CMD do not create a layer and are marked 'empty_layer'. Skipping
    those leaves exactly one history entry per layer, in the same order.
    """
    instructions = []
    for entry in history:
        if entry.get("empty_layer", False):
            continue
        instructions.append(clean_instruction(entry.get("created_by", "")))

    # Some images have incomplete history; never fail because of that.
    while len(instructions) < layer_count:
        instructions.append("(no history entry)")
    return instructions[:layer_count]


def safe_target(root: str, member_name: str) -> str | None:
    """Return the on-disk path for a tar member, or None if it is unsafe.

    A malicious tar could contain '../../etc/passwd' or an absolute path.
    We only allow paths that stay inside the extraction directory.
    """
    target = os.path.abspath(os.path.join(root, member_name))
    if not target.startswith(root + os.sep):
        return None
    return target


def remove_path(path: str) -> None:
    """Delete a file or directory if it exists."""
    if os.path.isdir(path) and not os.path.islink(path):
        shutil.rmtree(path, ignore_errors=True)
    elif os.path.lexists(path):
        os.remove(path)


def apply_whiteout(root: str, member_name: str) -> None:
    """Handle a whiteout entry, which marks a deletion from lower layers.

    '.wh.foo'       means 'foo' in this directory was deleted.
    '.wh..wh..opq'  means the whole directory was replaced, so everything
                    that lower layers put in it is deleted.
    """
    parent, base = os.path.split(member_name)

    if base == OPAQUE_WHITEOUT:
        directory = safe_target(root, parent) if parent else root
        if directory and os.path.isdir(directory):
            for child in os.listdir(directory):
                remove_path(os.path.join(directory, child))
        return

    deleted_name = base[len(WHITEOUT_PREFIX):]
    target = safe_target(root, os.path.join(parent, deleted_name))
    if target:
        remove_path(target)


def extract_layer(layer_file, root: str) -> dict:
    """Apply one layer tar on top of the directory 'root'.

    Only directories and regular files are written. Symlinks, hard links
    and device files are skipped: we only need file contents to read the
    package databases, and skipping links also means a link can never
    point a later write outside 'root'.

    Returns the layer's uncompressed content size, the text of any
    package database it contains, and how many files could not be written.
    """
    size = 0
    skipped = 0
    package_dbs = {}

    # "r|*" reads the layer as a stream and auto-detects gzip compression,
    # which is what `docker save` produces with the containerd image store.
    with tarfile.open(fileobj=layer_file, mode="r|*") as layer_tar:
        for member in layer_tar:
            name = member.name
            if name.startswith("./"):
                name = name[2:]
            name = name.rstrip("/")
            if name == "" or name == ".":
                continue

            if os.path.basename(name).startswith(WHITEOUT_PREFIX):
                apply_whiteout(root, name)
                continue

            target = safe_target(root, name)
            if target is None:
                skipped += 1
                continue

            try:
                if member.isdir():
                    if os.path.lexists(target) and not os.path.isdir(target):
                        remove_path(target)
                    os.makedirs(target, exist_ok=True)

                elif member.isfile():
                    size += member.size
                    if os.path.isdir(target):
                        remove_path(target)
                    os.makedirs(os.path.dirname(target), exist_ok=True)

                    source = layer_tar.extractfile(member)
                    if name in PACKAGE_DB_PATHS:
                        data = source.read()
                        package_dbs[name] = data.decode("utf-8", errors="replace")
                        with open(target, "wb") as out:
                            out.write(data)
                    else:
                        with open(target, "wb") as out:
                            shutil.copyfileobj(source, out)
            except OSError:
                # Linux allows file names that Windows does not (for example
                # names containing ':'). Skip them rather than abort.
                skipped += 1

    return {"size": size, "package_dbs": package_dbs, "skipped_files": skipped}


def unpack_image(tar_path: str, dest_dir: str) -> dict:
    """Extract every layer of the image at 'tar_path' into 'dest_dir'.

    Returns the image name, the per-layer details (size, instruction,
    package database snapshot) and the path of the rebuilt filesystem.
    """
    path = Path(tar_path)
    if not path.is_file():
        raise ImageError(f"file not found: {tar_path}")
    if not tarfile.is_tarfile(path):
        raise ImageError(f"not a tar file: {tar_path} (create one with `docker save`)")

    root = os.path.abspath(dest_dir)
    os.makedirs(root, exist_ok=True)

    with tarfile.open(path, mode="r") as image_tar:
        manifest = read_manifest(image_tar)
        config = read_json_member(image_tar, manifest["Config"])

        layer_names = manifest["Layers"]
        instructions = match_history_to_layers(config.get("history", []), len(layer_names))

        repo_tags = manifest.get("RepoTags") or []
        image_name = repo_tags[0] if repo_tags else path.stem

        layers = []
        for index, layer_name in enumerate(layer_names):
            try:
                layer_file = image_tar.extractfile(layer_name)
            except KeyError:
                raise ImageError(f"layer '{layer_name}' listed in manifest.json is missing")

            try:
                result = extract_layer(layer_file, root)
            except tarfile.TarError as error:
                raise ImageError(f"layer '{layer_name}' is not a readable tar: {error}")

            layers.append({
                "index": index,
                "digest": layer_name,
                "size": result["size"],
                "instruction": instructions[index],
                "package_dbs": result["package_dbs"],
                "skipped_files": result["skipped_files"],
            })

    return {
        "name": image_name,
        "root": root,
        "layers": layers,
        "total_size": sum(layer["size"] for layer in layers),
    }
