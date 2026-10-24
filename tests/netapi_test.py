# -*- coding: utf-8 -*-
#
import testify as T
from mock import patch

from threat_intel.netapi import NetApiRankingApi


class NetApiRankingApiTest(T.TestCase):

    """Tests requesting reports from NetApiRankingApi."""

    @T.setup
    def setup_na(self):
        self.na = NetApiRankingApi()

    def _test_api_call(self, call, request, expected_query_params, api_response, expected_result):
        """
        Tests a NetApiRankingApi call by mocking out the HTTP request.

        Args:
            call: Function in NetApiRankingApi to call.
            request: Call arguments.
            expected_query_params: Parameters that should be passed to API.
            api_response: The expected response by the API.
            expected_result: What the call should return.
        """
        with patch.object(self.na, '_requests') as request_mock:
            request_mock.multi_get.return_value = api_response
            result = call(request)
            request_mock.multi_get.assert_called_with(
                self.na.BASE_URL,
                query_params=expected_query_params,
            )
            T.assert_equal(result, expected_result)

    def test_get_domain_rankings_in_top_1m(self):
        api_response = {
            'domain': 'domain1.com',
            'in_top_1m': True,
            'rank': 1015,
            'snapshot_date': '2026-10-24',
            'tld': 'com',
            'rank_in_tld': 503,
            'tld_sites_in_top_1m': 428050,
            'note': 'Rank 1 = most popular.',
            'links': {'top_1m': 'https://netapi.com/top-1-mln-websites/'},
        }
        self._test_api_call(
            call=self.na.get_domain_rankings,
            request=['domain1.com'],
            expected_query_params=[{'method': 'domain-rank', 'domain': 'domain1.com'}],
            api_response=[api_response],
            expected_result={
                'domain1.com': {
                    'domain': 'domain1.com',
                    'in_top_1m': True,
                    'rank': 1015,
                    'rank_in_tld': 503,
                    'tld': 'com',
                    'tld_sites_in_top_1m': 428050,
                    'snapshot_date': '2026-10-24',
                },
            },
        )

    def test_get_domain_rankings_not_in_top_1m(self):
        api_response = {
            'domain': 'domain2.com',
            'in_top_1m': False,
            'rank': None,
            'snapshot_date': '2026-10-24',
            'tld': 'com',
            'rank_in_tld': None,
            'tld_sites_in_top_1m': 428050,
            'note': 'The domain is not in the current NetAPI Top 1M.',
        }
        self._test_api_call(
            call=self.na.get_domain_rankings,
            request=['domain2.com'],
            expected_query_params=[{'method': 'domain-rank', 'domain': 'domain2.com'}],
            api_response=[api_response],
            expected_result={
                'domain2.com': {
                    'domain': 'domain2.com',
                    'in_top_1m': False,
                    'rank': None,
                    'rank_in_tld': None,
                    'tld': 'com',
                    'tld_sites_in_top_1m': 428050,
                    'snapshot_date': '2026-10-24',
                },
            },
        )

    def test_get_domain_rankings_failed_request(self):
        self._test_api_call(
            call=self.na.get_domain_rankings,
            request=['domain3.com'],
            expected_query_params=[{'method': 'domain-rank', 'domain': 'domain3.com'}],
            api_response=[None],
            expected_result={'domain3.com': {'domain': 'domain3.com'}},
        )

    def test_get_domain_rankings_error_answer(self):
        self._test_api_call(
            call=self.na.get_domain_rankings,
            request=['not a domain'],
            expected_query_params=[{'method': 'domain-rank', 'domain': 'not a domain'}],
            api_response=[{'error': {'code': 'invalid_domain', 'message': 'Not a valid domain name.'}}],
            expected_result={'not a domain': {'domain': 'not a domain'}},
        )
