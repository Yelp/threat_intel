# -*- coding: utf-8 -*-
#
from contextlib import nested

import testify as T
from mock import ANY
from mock import mock_open
from mock import patch

from threat_intel.opendns import InvestigateApi
from threat_intel.opendns import ResponseError
from threat_intel.util.api_cache import ApiCache
from threat_intel.util.http import MultiRequest


class InvestigateApiTest(T.TestCase):

    """Tests requesting reports from OpenDNS."""

    @T.setup
    def setup_opendns(self):
        self.opendns = InvestigateApi('test_key')

    def _patch_and_assert_categorization(self, all_responses, expected_responses, domains, expected_url, expected_data):
        with patch.object(MultiRequest, 'multi_post', autospec=True, return_value=all_responses) as patched_multi_post:
            actual_responses = self.opendns.categorization(domains)

        patched_multi_post.assert_called_with(ANY, expected_url, data=expected_data)
        assert expected_responses == actual_responses

    def test_categorization(self):
        domains = ['yellowstone.org', 'zion.org', 'sequoia.org', 'greatsanddunes.org']
        all_responses = [
            {
                u'yellowstone.org': {
                    u'content_categories': [u'National Parks'],
                    u'security_categories': [],
                    u'status': 1
                },
                u'zion.org': {
                    u'content_categories': [u'National Parks'],
                    u'security_categories': [],
                    u'status': 1
                },
                u'sequoia.org': {
                    u'content_categories': [u'National Parks'],
                    u'security_categories': [],
                    u'status': 1
                },
                u'greatsanddunes.org': {
                    u'content_categories': [u'National Parks'],
                    u'security_categories': [],
                    u'status': 1
                }
            }
        ]

        expected_url = u'https://investigate.api.opendns.com/domains/categorization/?showLabels'
        expected_data = ['["yellowstone.org", "zion.org", "sequoia.org", "greatsanddunes.org"]']
        expected_responses = all_responses[0]

        self._patch_and_assert_categorization(all_responses, expected_responses, domains, expected_url, expected_data)

    def test_categorization_domains_limit(self):
        self.opendns.MAX_DOMAINS_IN_POST = 2
        domains = [
            'northyorkmoors.org.uk', 'peakdistrict.org.uk',
            'cairngorms.org.uk', 'pembrokeshirecoast.org.uk',
            'northumberland.org.uk']
        all_responses = [
            {
                u'northyorkmoors.org.uk': {
                    u'content_categories': [u'National Parks'],
                    u'security_categories': [],
                    u'status': 1
                },
                u'peakdistrict.org.uk': {
                    u'content_categories': [u'National Parks'],
                    u'security_categories': [],
                    u'status': 1
                },
            },
            {
                u'cairngorms.org.uk': {
                    u'content_categories': [u'National Parks'],
                    u'security_categories': [],
                    u'status': 1
                },
                u'pembrokeshirecoast.org.uk': {
                    u'content_categories': [u'National Parks'],
                    u'security_categories': [],
                    u'status': 1
                },
            },
            {
                u'northumberland.org.uk': {
                    u'content_categories': [u'National Parks'],
                    u'security_categories': [],
                    u'status': 1
                }
            }
        ]

        expected_data = [
            '["northyorkmoors.org.uk", "peakdistrict.org.uk"]',
            '["cairngorms.org.uk", "pembrokeshirecoast.org.uk"]',
            '["northumberland.org.uk"]']
        expected_responses = {
            u'northyorkmoors.org.uk': {
                u'content_categories': [u'National Parks'],
                u'security_categories': [],
                u'status': 1
            },
            u'peakdistrict.org.uk': {
                u'content_categories': [u'National Parks'],
                u'security_categories': [],
                u'status': 1
            },
            u'cairngorms.org.uk': {
                u'content_categories': [u'National Parks'],
                u'security_categories': [],
                u'status': 1
            },
            u'pembrokeshirecoast.org.uk': {
                u'content_categories': [u'National Parks'],
                u'security_categories': [],
                u'status': 1
            },
            u'northumberland.org.uk': {
                u'content_categories': [u'National Parks'],
                u'security_categories': [],
                u'status': 1
            }
        }

        self._patch_and_assert_categorization(all_responses, expected_responses, domains, ANY, expected_data)

    def test_categorization_response_error(self):
        """Tests whether the ResponseError is raised when the response
        returned from the actual API call is empty.
        """
        domains = ['yosemite.gov', 'joushuatree.gov', 'deathvalley.gov']
        # empty responses should raise an error
        all_responses = [{}]

        # mock cache file
        mock_read = mock_open(read_data="{}")

        with nested(
            patch('__builtin__.open', mock_read, create=True),
            patch.object(
                ApiCache, 'bulk_lookup', autospec=True, return_value={}),
            patch.object(
                MultiRequest, 'multi_post', autospec=True,
                return_value=all_responses),
        ) as (__, __, patched_multi_post):
            i = InvestigateApi('hocus pocus', 'cache.json')
            with T.assert_raises(ResponseError):
                i.categorization(domains)

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

    def test_whois_emails(self):
        self._test_api_call_get(call=self.opendns.whois_emails,
                                endpoint=u'whois/emails/{0}',
                                request=['admin@dns.com'],
                                expected_query_params='admin@dns.com',
                                api_response={},
                                expected_result={})

    def test_whois_nameservers(self):
        self._test_api_call_get(call=self.opendns.whois_nameservers,
                                endpoint=u'whois/nameservers/{0}',
                                request=['ns.dns.com'],
                                expected_query_params='ns.dns.com',
                                api_response={},
                                expected_result={})

    def test_whois_domains(self):
        self._test_api_call_get(call=self.opendns.whois_domains,
                                endpoint=u'whois/{0}',
                                request=['google.com'],
                                expected_query_params='google.com',
                                api_response={},
                                expected_result={})

    def test_whois_domains_history(self):
        self._test_api_call_get(call=self.opendns.whois_domains_history,
                                endpoint=u'whois/{0}/history',
                                request=['5esb.biz'],
                                expected_query_params='5esb.biz',
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
