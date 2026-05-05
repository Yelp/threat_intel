# -*- coding: utf-8 -*-
#
import testify as T
from mock import patch
from mock import ANY

from threat_intel.virustotal import VirusTotalApi
from threat_intel.util.http import MultiRequest


class VirusTotalApiTest(T.TestCase):

    """Tests requesting reports from VirusTotalApi."""

    @T.setup
    def setup_vt(self):
        self.vt = VirusTotalApi('test_key')

    def test_gti_assessment_sets_x_tool_header(self):
        """When gti_assessment is provided, x-tool header should be included in requests."""
        with patch.object(MultiRequest, '__init__', return_value=None) as mock_init:
            VirusTotalApi('test_key', gti_assessment='my-tool')
            mock_init.assert_called_once_with(
                req_timeout=None,
                default_headers={'x-apikey': 'test_key', 'x-tool': 'my-tool'},
                drop_404s=True,
            )

    def test_no_gti_assessment_omits_x_tool_header(self):
        """When gti_assessment is not provided, x-tool header should not be present."""
        with patch.object(MultiRequest, '__init__', return_value=None) as mock_init:
            VirusTotalApi('test_key')
            mock_init.assert_called_once_with(
                req_timeout=None,
                default_headers={'x-apikey': 'test_key'},
                drop_404s=True,
            )

    def test_empty_gti_assessment_omits_x_tool_header(self):
        """When gti_assessment is an empty string, x-tool header should not be set."""
        with patch.object(MultiRequest, '__init__', return_value=None) as mock_init:
            VirusTotalApi('test_key', gti_assessment='')
            mock_init.assert_called_once_with(
                req_timeout=None,
                default_headers={'x-apikey': 'test_key'},
                drop_404s=True,
            )

    def _test_api_call(self, call, endpoint, request, expected_query_params, api_response, expected_result):
        """
        Tests a VirusTotalApi call by mocking out the HTTP request.

        Args:
            call: function in VirusTotalApi to call.
            endpoint: endpoint of VirusTotal API that is hit (appended to base url)
            request: call arguments
            expected_query_params: query parameters that should be passed to API
            api_response: the expected response by the API
            expected_result: what call should return (given the api response provided)
        """
        with patch.object(self.vt, '_requests') as request_mock:
            request_mock.multi_get.return_value = api_response
            result = call(request)
            param_list = [self.vt.BASE_DOMAIN + endpoint.format(param) for param in expected_query_params]
            request_mock.multi_get.assert_called_with(param_list, file_download=ANY)
            T.assert_equal(result, expected_result)

    def test_get_file_reports(self):
        self._test_api_call(call=self.vt.get_file_reports,
                            endpoint='files/{}',
                            request=['file1', 'file2'],
                            expected_query_params=['file1', 'file2'],
                            api_response=[{'data':{'id': 'file1'}}, {'data':{'id': 'file2'}}],
                            expected_result={'file1': {'data': {'id': 'file1'}},
                                             'file2': {'data': {'id': 'file2'}}})

    def test_get_file_behaviour(self):
        self._test_api_call(call=self.vt.get_file_behaviour,
                            endpoint='files/{}/behaviours',
                            request=['file1', 'file2'],
                            expected_query_params=['file1', 'file2'],
                            api_response=[{'data':{'id': 'file1'}}, {'data':{'id': 'file2'}}],
                            expected_result={'file1': {'data': {'id': 'file1'}},
                                             'file2': {'data': {'id': 'file2'}}})

    def test_get_file_download(self):
        self._test_api_call(call=self.vt.get_file_download,
                            endpoint='files/{}/download',
                            request=['file1', 'file2'],
                            expected_query_params=['file1', 'file2'],
                            api_response=[{'data':{'id': 'file1'}}, {'data':{'id': 'file2'}}],
                            expected_result={'file1': {'data': {'id': 'file1'}},
                                             'file2': {'data': {'id': 'file2'}}})

    def test_get_domain_reports(self):
        self._test_api_call(call=self.vt.get_domain_reports,
                            endpoint='domains/{}',
                            request=['domain1', 'domain2'],
                            expected_query_params=['domain1', 'domain2'],
                            api_response=[{}, {}],
                            expected_result={'domain1': {},
                                             'domain2': {}})

    def test_get_url_reports(self):
        self._test_api_call(call=self.vt.get_url_reports,
                            endpoint='urls/{}',
                            request=['url1', 'url2'],
                            expected_query_params = ['url1', 'url2'],
                            api_response=[{'data':{'id': 'url1'}}, {'data':{'id': 'url2'}}],
                            expected_result={'url1': {'data': {'id': 'url1'}},
                                             'url2': {'data': {'id': 'url2'}}})

    def test_get_ip_reports(self):
        self._test_api_call(call=self.vt.get_ip_reports,
                            endpoint='ip_addresses/{}',
                            request=['ip1', 'ip2'],
                            expected_query_params=['ip1', 'ip2'],
                            api_response=[{}, {}],
                            expected_result={'ip1': {},
                                             'ip2': {}})

    def test_get_file_contacted_domains(self):
        self._test_api_call(call=self.vt.get_file_contacted_domains,
                            endpoint='files/{}/contacted_domains',
                            request=['domain1', 'domain2'],
                            expected_query_params=['domain1', 'domain2'],
                            api_response=[{'data':{'id': 'domain1'}}, {'data':{'id': 'domain2'}}],
                            expected_result={'domain1': {'data': {'id': 'domain1'}},
                                             'domain2': {'data': {'id': 'domain2'}}})

    def test_get_file_contacted_ips(self):
        self._test_api_call(call=self.vt.get_file_contacted_ips,
                            endpoint='files/{}/contacted_ips',
                            request=['file1', 'file2'],
                            expected_query_params=['file1', 'file2'],
                            api_response=[{'data':{'id': 'file1'}}, {'data':{'id': 'file2'}}],
                            expected_result={'file1': {'data': {'id': 'file1'}},
                                             'file2': {'data': {'id': 'file2'}}})

    def test_get_file_contacted_urls(self):
        self._test_api_call(call=self.vt.get_file_contacted_urls,
                            endpoint='files/{}/contacted_urls',
                            request=['file1', 'file2'],
                            expected_query_params=['file1', 'file2'],
                            api_response=[{'data':{'id': 'file1'}}, {'data':{'id': 'file2'}}],
                            expected_result={'file1': {'data': {'id': 'file1'}},
                                             'file2': {'data': {'id': 'file2'}}})

    def test_get_file_itw_urls(self):
        self._test_api_call(call=self.vt.get_file_itw_urls,
                            endpoint='files/{}/itw_urls',
                            request=['file1', 'file2'],
                            expected_query_params=['file1', 'file2'],
                            api_response=[{'data':{'id': 'file1'}}, {'data':{'id': 'file2'}}],
                            expected_result={'file1': {'data': {'id': 'file1'}},
                                             'file2': {'data': {'id': 'file2'}}})

    def test_get_domain_communicating_files(self):
        self._test_api_call(call=self.vt.get_domain_communicating_files,
                            endpoint='domains/{}/communicating_files',
                            request=['domain1', 'domain2'],
                            expected_query_params=['domain1', 'domain2'],
                            api_response=[{'data':{'id': 'domain1'}}, {'data':{'id': 'domain2'}}],
                            expected_result={'domain1': {'data': {'id': 'domain1'}},
                                             'domain2': {'data': {'id': 'domain2'}}})

    def test_get_domain_referrer_files(self):
        self._test_api_call(call=self.vt.get_domain_referrer_files,
                            endpoint='domains/{}/referrer_files',
                            request=['domain1', 'domain2'],
                            expected_query_params=['domain1', 'domain2'],
                            api_response=[{'data':{'id': 'domain1'}}, {'data':{'id': 'domain2'}}],
                            expected_result={'domain1': {'data': {'id': 'domain1'}},
                                             'domain2': {'data': {'id': 'domain2'}}})
    def test_get_domain_reports(self):
        self._test_api_call(call=self.vt.get_domain_reports,
                            endpoint='domains/{}',
                            request=['domain1', 'domain2'],
                            expected_query_params=['domain1', 'domain2'],
                            api_response=[{}, {}],
                            expected_result={'domain1': {},
                                             'domain2': {}})

    def test_get_file_clusters(self):
        self._test_api_call(call=self.vt.get_file_clusters,
                            endpoint='feeds/file-behaviours/{}',
                            request=['time1', 'time2'],
                            expected_query_params=['time1', 'time2'],
                            api_response=[{'data':{'id': 'time1'}}, {'data':{'id': 'time2'}}],
                            expected_result={'time1': {'data': {'id': 'time1'}},
                                             'time2': {'data': {'id': 'time2'}}})
