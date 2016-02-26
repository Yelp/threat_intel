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

    def test_multi_get_max_retries(self):
        """Tests the exception handling in case the number of the maximum retries is reached, due to the empty responses."""
        # mock responses
        responses = [MagicMock()] * 10
        for response in responses:
            response.status_code = 200
        responses[7] = None

        query_params = [{'John Fitzgerald': 'Tom Hardy'}] * 10

        says_max_retries = lambda e: T.assert_equal(str(e), 'Unable to complete batch of requests within 10 retries')
        with nested(
            patch('grequests.map', return_value=responses),
            T.assert_raises_such_that(InvalidRequestError, says_max_retries)
        ) as (patched_grequests_map, __):
            MultiRequest().multi_get('example.com', query_params)

        T.assert_equal(10, patched_grequests_map.call_count)

    def test_multi_get_expected_json_response(self):
        """Tests the exception handling in the cases when the response was supposed to return JSON but did not."""
        # mock responses
        responses = [MagicMock()] * 5
        for response in responses:
            response.status_code = 200

        # mock the exception raised in case response cannot be converted to JSON
        # based on: http://docs.python-requests.org/en/master/user/quickstart/#json-response-content
        responses[3].json.side_effect = ValueError('No JSON object could be decoded')
        responses[3].request.url = 'example.com/movie'

        query_params = [{'Andrew Henry': 'Domhnall Gleeson'}] * 5

        says_expected_json_response = lambda e: T.assert_equal(str(e), 'Expected JSON response from: example.com/movie')
        with nested(
            patch('grequests.map', return_value=responses),
            T.assert_raises_such_that(InvalidRequestError, says_expected_json_response)
        ):
            MultiRequest().multi_get('example.com', query_params)
