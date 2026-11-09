"""Allow `python -m imagex ...` as well as the installed `imagex` command."""

import sys

from imagex.cli import main

sys.exit(main())
