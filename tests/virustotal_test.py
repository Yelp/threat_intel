# -*- coding: utf-8 -*-
#
import testify as T
from mock import patch

from threat_intel.virustotal import VirusTotalApi


class VirusTotalApiTest(T.TestCase):

    """Tests requesting reports from VirusTotalApi."""

    @T.setup
    def setup_vt(self):
        self.vt = VirusTotalApi('test_key')

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

            request_mock.multi_get.assert_called_with(self.vt.BASE_DOMAIN + endpoint, query_params=expected_query_params)
            T.assert_equal(result, expected_result)

    def test_get_file_reports(self):
        self._test_api_call(call=self.vt.get_file_reports,
                            endpoint='file/report',
                            request=['file1', 'file2'],
                            expected_query_params=[{'resource': 'file1,file2',
                                                    'apikey': 'test_key'}],
                            api_response=[{'resource': 'file1'}, {'resource': 'file2'}],
                            expected_result={'file1': {'resource': 'file1'},
                                             'file2': {'resource': 'file2'}})

    def test_get_file_behaviour(self):
        self._test_api_call(call=self.vt.get_file_behaviour,
                            endpoint='file/behaviour',
                            request=['file1', 'file2'],
                            expected_query_params=[{'resource': 'file1,file2',
                                                    'apikey': 'test_key'}],
                            api_response=[{'resource': 'file1'}, {'resource': 'file2'}],
                            expected_result={'file1': {'resource': 'file1'},
                                             'file2': {'resource': 'file2'}})

    def test_get_file_network_traffic(self):
        self._test_api_call(call=self.vt.get_file_network_traffic,
                            endpoint='file/network-traffic',
                            request=['file1', 'file2'],
                            expected_query_params=[{'resource': 'file1,file2',
                                                    'apikey': 'test_key'}],
                            api_response=[{'resource': 'file1'}, {'resource': 'file2'}],
                            expected_result={'file1': {'resource': 'file1'},
                                             'file2': {'resource': 'file2'}})

    def test_get_file_download(self):
        self._test_api_call(call=self.vt.get_file_download,
                            endpoint='file/download',
                            request=['file1', 'file2'],
                            expected_query_params=[{'resource': 'file1,file2',
                                                    'apikey': 'test_key'}],
                            api_response=[{'resource': 'file1'}, {'resource': 'file2'}],
                            expected_result={'file1': {'resource': 'file1'},
                                             'file2': {'resource': 'file2'}})

    def test_get_domain_reports(self):
        self._test_api_call(call=self.vt.get_domain_reports,
                            endpoint='domain/report',
                            request=['domain1', 'domain2'],
                            expected_query_params=[{'domain': 'domain1',
                                                    'apikey': 'test_key'},
                                                   {'domain': 'domain2',
                                                    'apikey': 'test_key'}],
                            api_response=[{}, {}],
                            expected_result={'domain1': {},
                                             'domain2': {}})

    def test_get_url_reports(self):
        self._test_api_call(call=self.vt.get_url_reports,
                            endpoint='url/report',
                            request=['url1', 'url2'],
                            expected_query_params=[{'resource': 'url1\nurl2',
                                                    'apikey': 'test_key'}],
                            api_response=[{'resource': 'url1'}, {'resource': 'url2'}],
                            expected_result={'url1': {'resource': 'url1'},
                                             'url2': {'resource': 'url2'}})

    def test_get_ip_reports(self):
        self._test_api_call(call=self.vt.get_ip_reports,
                            endpoint='ip-address/report',
                            request=['ip1', 'ip2'],
                            expected_query_params=[{'ip': 'ip1',
                                                    'apikey': 'test_key'},
                                                   {'ip': 'ip2',
                                                    'apikey': 'test_key'}],
                            api_response=[{}, {}],
                            expected_result={'ip1': {},
                                             'ip2': {}})
