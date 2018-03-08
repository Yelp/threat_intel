# -*- coding: utf-8 -*-
#
import testify as T
from mock import patch

from threat_intel.alexaranking import AlexaRankingApi

from requests.models import Response


class AlexaRankingApiTest(T.TestCase):

    """Tests requesting reports from AlexaRankingApi."""

    def mock_ok_response(self):
        """Mocks a successful request response."""
        content_ok = open("tests/data/response.xml").read()
        response = Response()
        response.status_code = 200
        response._content = content_ok
        return response

    def mock_bad_response(self):
        """Mocks an unsuccessful request response."""
        response = Response()
        content_bad = u'Internal Server Error'.encode('utf-8')
        response.status_code = 400
        response._content = content_bad
        return response

    @T.setup
    def setup_ar(self):
        self.ar = AlexaRankingApi()

    def _test_api_call(
            self, call, request, expected_query_params, api_response,
            expected_result):
        """
        Tests a AlexaRankingApi call by mocking out the HTTP request.

        Args:
            call: Function in AlexaRankingApi to call.
            endpoint: Endpoint of AlexaRanking API that is hit.
            request: Call arguments.
            expected_query_params: Parameters that should be passed to API.
            api_response: The expected response by the API.
            expected_result: What the call should return.
        """
        with patch.object(self.ar, '_requests') as request_mock:
            request_mock.multi_get.return_value = api_response
            result = call(request)
            request_mock.multi_get.assert_called_with(
                self.ar.BASE_URL,
                to_json=False,
                query_params=expected_query_params)
            T.assert_equal(result, expected_result)

    def test_get_alexa_rankings_good_response(self):
        successful_response = self.mock_ok_response()
        self._test_api_call(call=self.ar.get_alexa_rankings,
                            request=['domain1.com'],
                            expected_query_params=[{'url': 'domain1.com'}],
                            api_response=[successful_response],
                            expected_result={
                                "domain1.com": {
                                    "attributes": {
                                        "domain": "domain1.com",
                                        "popularity": "81743",
                                        "reach": "76276",
                                        "rank": "-67329"
                                    }
                                }
                            })

    def test_get_alexa_rankings_bad_response(self):
        unsuccessful_response = self.mock_bad_response()
        self._test_api_call(call=self.ar.get_alexa_rankings,
                            request=['domain2.com'],
                            expected_query_params=[{'url': 'domain2.com'}],
                            api_response=[unsuccessful_response],
                            expected_result={
                                "domain2.com": {
                                    "attributes": {
                                        "domain": "domain2.com"
                                    }
                                }
                            })
