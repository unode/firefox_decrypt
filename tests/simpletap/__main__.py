"""Main entry point"""

import sys

from unittest.main import main, TestProgram, USAGE_AS_MAIN
from .runner import TAPTestRunner


if sys.argv[0].endswith("__main__.py"):
    sys.argv[0] = "python3 -m simpletap"

__unittest = True

TestProgram.USAGE = USAGE_AS_MAIN

main(module=None, testRunner=TAPTestRunner())
