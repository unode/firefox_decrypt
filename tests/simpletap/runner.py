# simpletap - "Simple" TAP output with unittest
#
# Copyright (c) 2014-2016 Renato Alves
#
# This code is released under the MIT license.
# Refer to LICENSE for further details.

import unittest
import warnings
from unittest.signals import registerResult

from .result import TAPTestResult


class TAPTestRunner(unittest.runner.TextTestRunner):
    """A test runner that displays results using the Test Anything Protocol
    syntax.

    Inherits from TextTestRunner the default runner.
    """
    resultclass = TAPTestResult

    def run(self, test):
        result = self._makeResult()
        registerResult(result)
        result.failfast = self.failfast
        result.buffer = self.buffer

        with warnings.catch_warnings():
            if getattr(self, "warnings", None):
                # if self.warnings is set, use it to filter all the warnings
                warnings.simplefilter(self.warnings)
                # if the filter is 'default' or 'always', special-case the
                # warnings from the deprecated unittest methods to show them
                # no more than once per module, because they can be fairly
                # noisy.  The -Wd and -Wa flags can be used to bypass this
                # only when self.warnings is None.
                if self.warnings in ['default', 'always']:
                    warnings.filterwarnings(
                        'module',
                        category=DeprecationWarning,
                        message='Please use assert\w+ instead.')
            startTestRun = getattr(result, 'startTestRun', None)
            if startTestRun is not None:
                result.total_tests = test.countTestCases()
                startTestRun()
            try:
                test(result)
            finally:
                stopTestRun = getattr(result, 'stopTestRun', None)
                if stopTestRun is not None:
                    stopTestRun()

        return result
