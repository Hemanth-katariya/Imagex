#!/usr/bin/env bash
# Pull a list of test images and save each one as a tar in ./images/.
# imagex never talks to a registry itself; this script is the only
# place that does, so the tool can be run fully offline afterwards.
#
# Usage:  ./scripts/fetch_images.sh            (default image list)
#         ./scripts/fetch_images.sh nginx:1.27 (your own list)

set -euo pipefail

if [ "$#" -gt 0 ]; then
    IMAGES=("$@")
else
    IMAGES=(
        "python:3.12"
        "python:3.12-slim"
        "node:22"
        "node:22-alpine"
        "alpine:3.20"
    )
fi

OUT_DIR="./images"
mkdir -p "$OUT_DIR"

for image in "${IMAGES[@]}"; do
    # python:3.12-slim -> python_3.12-slim.tar (":" and "/" are not
    # safe in file names on every OS).
    file_name="$(echo "$image" | tr ':/' '__').tar"

    echo "==> pulling $image"
    docker pull "$image"

    echo "==> saving $image to $OUT_DIR/$file_name"
    docker save "$image" -o "$OUT_DIR/$file_name"
done

echo "done. tars are in $OUT_DIR/"
ls -lh "$OUT_DIR"
