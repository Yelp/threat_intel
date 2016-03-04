# -*- coding: utf-8 -*-
import logging

import grequests
import testify as T
from mock import MagicMock
from requests.models import Response

from threat_intel.exceptions import InvalidRequestError
from threat_intel.util.http import MultiRequest


class MultiRequestTest(T.TestCase):

    def mock_ok_responses(self, number_of_responses):
        """Mocks `number_of_responses` response mocks. All of them are with the "200 OK" HTTP status code."""
        responses = [Response() for _ in range(number_of_responses)]
        for response in responses:
            response.status_code = 200
            response._content = '{"Director": "Alejandro González Iñárritu"}'
        return responses

    def mock_forbidden_response(self, response):
        """Mocks forbidden response by changing its status code to 403 and the content to indicate the error."""
        response.status_code = 403
        response._content = 'Forbidden'

    def mock_unsuccessful_response(self, response):
        """Mocks unsuccessful response by changing its status code to 500 and the content to indicate the error."""
        response.status_code = 500
        response._content = 'Internal Server Error'

    def mock_unsuccessful_responses(self, responses):
        """Mocks unsuccessful responses by changing their status code to 500 and the content to indicate the error."""
        for response in responses:
            self.mock_unsuccessful_response(response)

    def mock_json_convertion_error(self, response):
        """Mocks the exception raised in case response cannot be converted to JSON.
        Based on http://docs.python-requests.org/en/master/user/quickstart/#json-response-content
        """
        response.json = MagicMock(side_effect=ValueError('No JSON object could be decoded'))
        response._content = 'This is not JSON'
        response.request = MagicMock()
        # this is necessary for the log message referencing the URL
        response.request.response = response

    def mock_grequests_map(self, responses):
        """Mocks `grequests.map()` method call returning `responses`."""
        grequests.map = MagicMock()
        grequests.map.return_value = responses

    def test_multi_get_none_response(self):
        """Tests the behavior of the `multi_get()` method when one of the responses from `grequests.map` is `None`."""
        number_of_requests = 10
        query_params = [{'Jim Bridger': 'Will Poulter'}] * number_of_requests
        responses = self.mock_ok_responses(number_of_requests)
        responses[3] = None
        self.mock_grequests_map(responses)

        actual_responses = MultiRequest(max_retry=1).multi_get('example.com', query_params)

        T.assert_equals(10, len(actual_responses))
        T.assert_is(None, actual_responses[3])

    def test_multi_get_access_forbidden(self):
        """Tests the exception handling in the cases when a request returns "403 Forbidden"."""
        number_of_requests = 20
        query_params = [{'Hugh Glass': 'Leonardo DiCaprio'}] * number_of_requests
        responses = self.mock_ok_responses(number_of_requests)
        self.mock_forbidden_response(responses[13])
        self.mock_grequests_map(responses)

        with T.assert_raises_such_that(InvalidRequestError, lambda e: T.assert_equal(str(e), 'Access forbidden')):
            MultiRequest().multi_get('example.com', query_params)

    def test_multi_get_max_retry(self):
        """Tests the case when the number of the maximum retries is reached, due to the unsuccessful responses.
        `grequests.map` is called 3 times (based on `max_retry`), each time there is only one successful response.
        Eventually the call to `multi_get` returns the responses among which one is unsuccessful (`None`).
        """
        number_of_requests = 4
        query_params = [{'John Fitzgerald': 'Tom Hardy'}] * number_of_requests
        responses_to_calls = [
            self.mock_ok_responses(number_of_requests),
            self.mock_ok_responses(number_of_requests - 1),
            self.mock_ok_responses(number_of_requests - 2)
        ]
        # mock unsuccessful responses to the first call to grequests.map
        self.mock_unsuccessful_responses(responses_to_calls[0][0:3])
        # mock unsuccessful responses to the second call to grequests.map
        self.mock_unsuccessful_responses(responses_to_calls[1][1:3])
        # mock unsuccessful response to the third call to grequests.map
        self.mock_unsuccessful_response(responses_to_calls[2][1])
        grequests.map = MagicMock()
        grequests.map.side_effect = responses_to_calls

        actual_responses = MultiRequest(max_retry=3).multi_get('example.com', query_params)

        T.assert_equal(3, grequests.map.call_count)
        T.assert_is(None, actual_responses[2])

    def test_multi_get_response_to_json(self):
        """Tests the exception handling in the cases when the response was supposed to return JSON but did not."""
        number_of_requests = 5
        query_params = [{'Andrew Henry': 'Domhnall Gleeson'}] * number_of_requests
        responses = self.mock_ok_responses(number_of_requests)
        self.mock_json_convertion_error(responses[3])
        self.mock_grequests_map(responses)
        logging.warning = MagicMock()

        actual_responses = MultiRequest().multi_get('example.com', query_params)

        T.assert_equals(5, len(actual_responses))
        T.assert_is(None, actual_responses[3])
        logging.warning.called_once_with(
            'Expected response in JSON format from example.com/movie/TheRevenant but the actual response text is: This is not JSON')

    def assert_only_unsuccessful_requests(self, call, unsuccessful_responses):
        """Asserts that the requests in call where only the ones that failed, based on the `unsuccessful_responses` list."""
        requests = call[0][0]
        T.assert_equal(len(unsuccessful_responses), len(requests))

    def test_multi_get_retry_only_unsuccessful_requests(self):
        """Tests whether only the unsuccessful requests are passed to the consequitive calls to `grequests.map()`.
        The calls to `grequests.map()` return 3 unsuccessful responses to the first call and then 2 unsuccessful responses to the second.
        The third (and the last) call to `grequests.map()` returns successful responses only.
        """
        responses_to_calls = [
            self.mock_ok_responses(10),
            self.mock_ok_responses(3),
            self.mock_ok_responses(2)
        ]
        # mock unsuccessful responses to the first call to grequests.map
        unsuccessful_responses_first_call = [
            responses_to_calls[0][2],
            responses_to_calls[0][3],
            responses_to_calls[0][5],
        ]
        self.mock_unsuccessful_responses(unsuccessful_responses_first_call)
        # mock unsuccessful responses to the second call to grequests.map
        unsuccessful_responses_second_call = [
            responses_to_calls[1][0],
            responses_to_calls[1][2],
        ]
        self.mock_unsuccessful_responses(unsuccessful_responses_second_call)
        grequests.map = MagicMock()
        grequests.map.side_effect = responses_to_calls

        query_params = [
            {'Max Rockatansky': 'Tom Hardy'},
            {'Imperator Furiosa': 'Charlize Theron'},
            {'Nux': 'Nicholas Hoult'},
            {'Immortan Joe': 'Hugh Keays-Byrne'},
            {'Slit': 'Josh Helman'},
            {'Rictus Erectus': 'Nathan Jones'},
            {'Toast the Knowing': 'Zoë Kravitz'},
            {'The Splendid Angharad': 'Rosie Huntington-Whiteley'},
            {'Capable': 'Riley Keough'},
            {'The Dag': 'Abbey Lee'},
        ]

        MultiRequest().multi_get('example.com', query_params)

        T.assert_equals(3, grequests.map.call_count)
        # assert that only the failed requests from the first call to grequests.map are passed in the second call
        second_call = grequests.map.call_args_list[1]
        self.assert_only_unsuccessful_requests(second_call, unsuccessful_responses_first_call)
        # assert that only the failed requests from the second call to grequests.map are passed in the third call
        third_call = grequests.map.call_args_list[2]
        self.assert_only_unsuccessful_requests(third_call, unsuccessful_responses_second_call)
