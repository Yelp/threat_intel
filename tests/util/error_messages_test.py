# -*- coding: utf-8 -*-
from six import StringIO

import testify as T
from mock import patch

from threat_intel.exceptions import InvalidRequestError
from threat_intel.util.error_messages import write_error_message
from threat_intel.util.error_messages import write_exception


class StdErrTestCase(T.TestCase):

    """Mocks out sys.stderr"""

    @T.setup_teardown
    def setupStringIO(self):
        self._stringio = StringIO()
        with patch('sys.stderr', self._stringio):
            yield


class WriteExceptionTest(StdErrTestCase):

    def test_simple_exception(self):
        try:
            raise Exception()
        except Exception as e:
            write_exception(e)

        output = self._stringio.getvalue()
        T.assert_equal(0, output.find('[ERROR]'))

    def test_specific_exception(self):
        try:
            raise InvalidRequestError()
        except Exception as e:
            write_exception(e)

        output = self._stringio.getvalue()
        T.assert_equal(0, output.find('[ERROR] InvalidRequestError'))

    def test_exception_message(self):
        try:
            raise InvalidRequestError('Look for me in validation')
        except Exception as e:
            write_exception(e)

        output = self._stringio.getvalue()
        T.assert_equal(0, output.find('[ERROR] InvalidRequestError Look for me in validation'))


class WriteErrorMessageTest(StdErrTestCase):

    def test_write_error_message(self):
        message = 'Look for me in validation'
        expected = '[ERROR] Look for me in validation\n'

        write_error_message(message)

        output = self._stringio.getvalue()
        T.assert_equal(output, expected)
