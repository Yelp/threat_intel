# -*- coding: utf-8 -*-
from contextlib import nested

import testify as T
from mock import MagicMock
from mock import patch

from threat_intel.exceptions import InvalidRequestError
from threat_intel.util.http import MultiRequest


class MultiRequestTest(T.TestCase):

    def mock_responses(self):
        """Creates a bunch of response mocks, with the '200 OK' HTTP status code."""
        responses = [MagicMock()] * 20
        for response in responses:
            response.status_code = 200
        return responses

    def patch_grequests_map_and_assert_raises_invalid_request_error(self, responses, exception_test):
        """Patches a call to `grequest.map` returning the list of `responses`.
        Verifies that the exception of type `InvalidRequestError` was raised and that it passes the `exception_test`.

        Returns:
            Patched `grequests.map` method
        """
        query_params = [{'Hugh Glass': 'Leonardo DiCaprio'}] * 20
        with nested(
            patch('grequests.map', return_value=responses),
            T.assert_raises_such_that(InvalidRequestError, exception_test)
        ) as (patched_grequests_map, __):
            MultiRequest().multi_get('example.com', query_params)
        return patched_grequests_map

    def test_multi_get_access_forbidden(self):
        """Tests the exception handling in the cases when a request returns '403 Forbidden'."""
        responses = self.mock_responses()
        responses[13].status_code = 403

        says_access_forbidden = lambda e: T.assert_equal(str(e), 'Access forbidden')
        self.patch_grequests_map_and_assert_raises_invalid_request_error(responses, says_access_forbidden)

    def test_multi_get_max_retries(self):
        """Tests the exception handling in case the number of the maximum retries is reached, due to the empty responses."""
        responses = self.mock_responses()
        responses[7] = None

        says_max_retries = lambda e: T.assert_equal(str(e), 'Unable to complete batch of requests within 10 retries')
        patched_grequests_map = self.patch_grequests_map_and_assert_raises_invalid_request_error(responses, says_max_retries)

        # the default number of retries is 10
        T.assert_equal(10, patched_grequests_map.call_count)

    def test_multi_get_expected_json_response(self):
        """Tests the exception handling in the cases when the response was supposed to return JSON but did not."""
        responses = self.mock_responses()

        # mock the exception raised in case response cannot be converted to JSON
        # based on: http://docs.python-requests.org/en/master/user/quickstart/#json-response-content
        responses[3].json.side_effect = ValueError('No JSON object could be decoded')
        responses[3].request.url = 'example.com/movie'

        says_expected_json_response = lambda e: T.assert_equal(str(e), 'Expected JSON response from: example.com/movie')
        self.patch_grequests_map_and_assert_raises_invalid_request_error(responses, says_expected_json_response)
