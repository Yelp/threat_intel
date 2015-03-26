# -*- coding: utf-8 -*-
#
import testify as T
from mock import patch

from threat_intel.opendns import InvestigateApi


class InvestigateApiTest(T.TestCase):

    """Tests requesting reports from OpenDNS."""

    @T.setup
    def setup_opendns(self):
        self.opendns = InvestigateApi('test_key')

    def _test_api_call_get(self, call, endpoint, request, expected_query_params, api_response, expected_result):
        """
        Tests a OpenDNS call by mocking out the HTTP GET request.

        Args:
            call: function in OpenDNSApi to call.
            endpoint: endpoint of OpenDNS API that is hit (appended to base url)
            request: call arguments
            expected_query_params: query parameters that should be passed to API
            api_response: the expected response by the API
            expected_result: what call should return (given the api response provided)
        """
        with patch.object(self.opendns, '_requests') as request_mock:
            request_mock.multi_get.return_value = api_response
            result = call(request)

            url = self.opendns._to_url(endpoint.format(expected_query_params))
            request_mock.multi_get.assert_called_with([url])
            T.assert_equal(result, expected_result)

    def test_security(self):
        self._test_api_call_get(call=self.opendns.security,
                            endpoint=u'security/name/{0}.json',
                            request=['domain'],
                            expected_query_params='domain',
                            api_response={},
                            expected_result={})

    def test_coocurrences(self):
        self._test_api_call_get(call=self.opendns.cooccurrences,
                            endpoint=u'recommendations/name/{0}.json',
                            request=['domain'],
                            expected_query_params='domain',
                            api_response={},
                            expected_result={})

    def test_rr_history(self):
        self._test_api_call_get(call=self.opendns.rr_history,
                            endpoint=u'dnsdb/ip/a/{0}.json',
                            request=['8.8.8.8'],
                            expected_query_params='8.8.8.8',
                            api_response={},
                            expected_result={})

    def test_latest_malicious(self):
        self._test_api_call_get(call=self.opendns.latest_malicious,
                            endpoint=u'ips/{0}/latest_domains',
                            request=['8.8.8.8'],
                            expected_query_params='8.8.8.8',
                            api_response={},
                            expected_result={})

    def test_domain_tag(self):
        self._test_api_call_get(call=self.opendns.domain_tag,
                            endpoint=u'domains/{0}/latest_tags',
                            request=['domain'],
                            expected_query_params='domain',
                            api_response={},
                            expected_result={})

    def test_dns_rr(self):
        self._test_api_call_get(call=self.opendns.dns_rr,
                            endpoint=u'dnsdb/name/a/{0}.json',
                            request=['domain'],
                            expected_query_params='domain',
                            api_response={},
                            expected_result={})

    def test_related_domains(self):
        self._test_api_call_get(call=self.opendns.related_domains,
                            endpoint=u'links/name/{0}.json',
                            request=['domain'],
                            expected_query_params='domain',
                            api_response={},
                            expected_result={})
