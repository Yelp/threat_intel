# -*- coding: utf-8 -*-
from contextlib import nested

import testify as T
from mock import MagicMock
from mock import patch

from threat_intel.exceptions import InvalidRequestError
from threat_intel.util.http import MultiRequest


class MultiRequestTest(T.TestCase):

    def test_multi_get_access_forbidden(self):
        """Tests the exception handling in the cases when a request returns '403 Forbidden'."""

        # mock responses
        responses = [MagicMock()] * 20
        for response in responses:
            response.status_code = 200
        responses[13].status_code = 403

        query_params = [{'Hugh Glass': 'Leonardo DiCaprio'}] * 20

        says_access_forbidden = lambda e: T.assert_equal(str(e), 'Access forbidden')
        with nested(
            patch('grequests.map', return_value=responses),
            T.assert_raises_such_that(InvalidRequestError, says_access_forbidden)
        ):
            MultiRequest().multi_get('example.com', query_params)
