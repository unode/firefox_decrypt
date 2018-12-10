"""
Test Anything Protocol extension to Python's unit testing framework

This module contains TAPTestRunner and TAPTestResult which are used to produce
a test report in a TAP compatible format. All remaining functionality comes
from Python's own unittest module.

The core of the tests does not need any change and is purely unittest code.
The sole difference is in the __name__ == "__main__" section.

Simple usage:

    import unittest

    class IntegerArithmeticTestCase(unittest.TestCase):
        def testAdd(self):  # test method names begin 'test*'
            "test adding values"
            self.assertEqual((1 + 2), 3)
            self.assertEqual(0 + 1, 1)

        def testMultiply(self):
            "test multiplying values"
            self.assertEqual((0 * 10), 0)
            self.assertEqual((5 * 8), 40)

        def testFail(self):
            "a failing test"
            self.assertEqual(0, 1)

        @unittest.expectedFailure
        def testExpectFail(self):
            "we saw this coming"
            self.assertEqual(0, 1)

        @unittest.skipIf(True, "Skipping this one")
        def testSkip(self):
            "pending a fix"
            self.assertEqual(0, 1)

        def testError(self):
            "oops something went wrong"
            no_such_variable + 1  # Oops!

    if __name__ == "__main__":
        from simpletap import TAPTestRunner
        unittest.main(testRunner=TAPTestRunner())


When saved in a file called ``test.py`` and executed would produce:

    1..6
    ok 1 - test.py: test adding values
    not ok 2 - test.py: oops something went wrong
    # ERROR: NameError on file test.py line 30 in testError: 'no_such_variable + 1  # Oops!':
    #        global name 'no_such_variable' is not defined
    skip 3 - test.py: we saw this coming
    # EXPECTED_FAILURE: AssertionError on file test.py line 21 in testExpectFail: 'self.assertEqual(0, 1)':
    #                   0 != 1
    not ok 4 - test.py: a failing test
    # FAIL: AssertionError on file test.py line 16 in testFail: 'self.assertEqual(0, 1)':
    #       0 != 1
    ok 5 - test.py: test multiplying values
    skip 6 - test.py: pending a fix
    # SKIP:
    #       Skipping this one


You can also launch simpletap directly from the command line in much the
same way you do with unittest:

    python3 -m simpletap test.IntegerArithmeticTestCase


For more information refer to the unittest documentation:

    http://docs.python.org/library/unittest.html

Copyright (c) 2014-2016 Renato Alves <alves.rjc@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

https://opensource.org/licenses/MIT
"""

from .result import TAPTestResult
from .runner import TAPTestRunner
from .version import __version__  # noqa


__all__ = ['TAPTestResult', 'TAPTestRunner']
