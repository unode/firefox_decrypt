# simpletap - "Simple" TAP output with unittest
#
# Copyright (c) 2014-2016 Renato Alves
#
# This code is released under the MIT license.
# Refer to LICENSE for further details.

import os
import sys
import unittest
import traceback
import inspect


class _WritelnDecorator(object):
    """Used to decorate file-like objects with a handy 'writeln' method"""
    def __init__(self, stream):
        self.stream = stream

    def __getattr__(self, attr):
        if attr in ('stream', '__getstate__'):
            raise AttributeError(attr)

        return getattr(self.stream, attr)

    def writeln(self, arg=None):
        if arg:
            self.write(arg)
        self.write('\n')  # text-mode streams translate to \r\n if needed


def _color(text, c):
    """
    Add color on the keyword that identifies the state of the test
    """
    if sys.stdout.isatty():
        clear = "\033[0m"

        colors = {
            "red": "\033[1m\033[91m",
            "yellow": "\033[1m\033[93m",
            "green": "\033[1m\033[92m",
        }
        return colors[c] + text + clear
    else:
        return text


class TAPTestResult(unittest.result.TestResult):
    def __init__(self, stream=sys.stderr, descriptions=True, verbosity=1):
        super(TAPTestResult, self).__init__(stream, descriptions, verbosity)
        self.stream = _WritelnDecorator(stream)
        self.descriptions = descriptions
        self.verbosity = verbosity
        # Buffer stdout and stderr
        self.buffer = True
        self.total_tests = "unk"

    def getDescription(self, test):
        doc_first_line = test.shortDescription()
        if self.descriptions and doc_first_line:
            return doc_first_line
        else:
            try:
                method = test._testMethodName
            except AttributeError:
                return "Preparation error on: {0}".format(test.description)
            else:
                return "{0} ({1})".format(method, test.__class__.__name__)

    def startTestRun(self):
        self.stream.writeln("1..{0}".format(self.total_tests))

    def stopTest(self, test):
        """Prevent flushing of stdout/stderr buffers until later"""
        pass

    def _restoreStdout(self):
        """Restore sys.stdout and sys.stderr, don't merge buffered output yet
        """
        if self.buffer:
            sys.stdout = self._original_stdout
            sys.stderr = self._original_stderr

    @staticmethod
    def _do_stream(data, stream):
        """Helper function for _mergeStdout"""
        for line in data.splitlines(True):
            # newlines should be taken literally and be comments in TAP
            line = line.replace("\\n", "\n# ")

            # Add a comment sign before each line
            if line.startswith("#"):
                stream.write(line)
            else:
                stream.write("# " + line)

        if not line.endswith('\n'):
            stream.write('\n')

    def _mergeStdout(self):
        """Merge buffered output with main streams
        """

        if self.buffer:
            output = self._stdout_buffer.getvalue()
            error = self._stderr_buffer.getvalue()
            if output:
                self._do_stream(output, sys.stdout)
            if error:
                self._do_stream(error, sys.stderr)

            self._stdout_buffer.seek(0)
            self._stdout_buffer.truncate()
            self._stderr_buffer.seek(0)
            self._stderr_buffer.truncate()

        # Needed to fix the stopTest override
        self._mirrorOutput = False

    def report(self, test, status=None, err=None):
        # Restore stdout/stderr but don't flush just yet
        self._restoreStdout()

        desc = self.getDescription(test)

        try:
            exception, msg, tb = err
        except (TypeError, ValueError):
            exception_name = ""
            msg = err
            tb = None
        else:
            exception_name = exception.__name__
            msg = str(msg)

        trace_msg = ""

        # Extract line where error happened for easier debugging
        trace = traceback.extract_tb(tb)
        # Iterate from the end and stop on first match
        for t in trace[::-1]:
            # t = (filename, line_number, function_name, raw_line)
            if t[2].startswith("test"):
                trace_msg = " on file {0} line {1} in {2}: '{3}'".format(*t)
                break

        # Retrieve the name of the file containing the test
        filename = os.path.basename(inspect.getfile(test.__class__))

        if status:

            if status == "SKIP":
                self.stream.writeln("{0} {1} - {2}: {3}".format(
                    _color("skip", "yellow"), self.testsRun, filename, desc)
                )
            elif status == "EXPECTED_FAILURE":
                self.stream.writeln("{0} {1} - {2}: {3}".format(
                    _color("skip", "yellow"), self.testsRun, filename, desc)
                )
            else:
                self.stream.writeln("{0} {1} - {2}: {3}".format(
                    _color("not ok", "red"), self.testsRun, filename, desc)
                )

            if exception_name:
                self.stream.writeln("# {0}: {1}{2}:".format(
                    status, exception_name, trace_msg)
                )
            else:
                self.stream.writeln("# {0}:".format(status))

            # Magic 3 is just for pretty indentation
            padding = " " * (len(status) + 3)

            for line in msg.splitlines():
                # Force displaying new-line characters as literal new lines
                line = line.replace("\\n", "\n# ")
                self.stream.writeln("#{0}{1}".format(padding, line))
        else:
            self.stream.writeln("{0} {1} - {2}: {3}".format(
                _color("ok", "green"), self.testsRun, filename, desc)
            )

        # Flush all buffers to stdout
        self._mergeStdout()

    def addSuccess(self, test):
        super(TAPTestResult, self).addSuccess(test)
        self.report(test)

    def addError(self, test, err):
        super(TAPTestResult, self).addError(test, err)
        self.report(test, "ERROR", err)

    def addFailure(self, test, err):
        super(TAPTestResult, self).addFailure(test, err)
        self.report(test, "FAIL", err)

    def addSkip(self, test, reason):
        super(TAPTestResult, self).addSkip(test, reason)
        self.report(test, "SKIP", reason)

    def addExpectedFailure(self, test, err):
        super(TAPTestResult, self).addExpectedFailure(test, err)
        self.report(test, "EXPECTED_FAILURE", err)

    def addUnexpectedSuccess(self, test):
        super(TAPTestResult, self).addUnexpectedSuccess(test)
        self.report(test, "UNEXPECTED_SUCCESS", str(test))
