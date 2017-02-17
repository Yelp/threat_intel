# -*- coding: utf-8 -*-
#
# VirusTotalApi makes calls to the VirusTotal API.
#
from six.moves import range

from threat_intel.util.api_cache import ApiCache
from threat_intel.util.http import MultiRequest


class VirusTotalApi(object):
    BASE_DOMAIN = u'https://www.virustotal.com/vtapi/v2/'

    def __init__(self, api_key, resources_per_req=25, cache_file_name=None, update_cache=True, req_timeout=None):
        """Establishes basic HTTP params and loads a cache.

        Args:
            api_key: VirusTotal API key
            resources_per_req: Maximum number of resources (hashes, URLs)
                to be send in a single request
            cache_file_name: String file name of cache.
            update_cache: Determines whether cache should be written out back to the disk when closing it.
                          Default is `True`.
            req_timeout: Maximum number of seconds to wait without reading a response byte before deciding an error has occurred.
                         Default is None.
        """
        self._api_key = api_key
        self._resources_per_req = resources_per_req
        self._requests = MultiRequest(req_timeout=req_timeout)

        # Create an ApiCache if instructed to
        self._cache = ApiCache(cache_file_name, update_cache) if cache_file_name else None

    @MultiRequest.error_handling
    def get_file_reports(self, resources):
        """Retrieves the most recent reports for a set of md5, sha1, and/or sha2 hashes.

        Args:
            resources: list of string hashes.
        Returns:
            A dict with the hash as key and the VT report as value.
        """
        api_name = 'virustotal-file-reports'

        all_responses, resources = self._bulk_cache_lookup(api_name, resources)
        resource_chunks = self._prepare_resource_chunks(resources)
        response_chunks = self._request_reports("resource", resource_chunks, 'file/report')
        self._extract_response_chunks(all_responses, response_chunks, api_name)

        return all_responses

    def _extract_all_responses(self, resources, api_endpoint, api_name):
        """ Aux function to extract all the API endpoint responses.

        Args:
            resources: list of string hashes.
            api_endpoint: endpoint path
            api_name: endpoint name
        Returns:
            A dict with the hash as key and the VT report as value.
        """
        all_responses, resources = self._bulk_cache_lookup(api_name, resources)
        resource_chunks = self._prepare_resource_chunks(resources)
        response_chunks = self._request_reports("resource", resource_chunks, api_endpoint)
        self._extract_response_chunks(all_responses, response_chunks, api_name)

        return all_responses

    @MultiRequest.error_handling
    def get_file_behaviour(self, resources):
        """Retrieves a report about the behaviour of a md5, sha1, and/or sha2 hash of
        a file when executed in a sandboxed environment (Cuckoo sandbox).

        Args:
            resources: list of string hashes.
        """
        api_name = 'virustotal-file-behaviour'
        api_endpoint = 'file/behaviour'
        return self._extract_all_responses(resources, api_endpoint, api_name)

    @MultiRequest.error_handling
    def get_file_download(self, resources):
        """Retrieves a file from its a md5, sha1, and/or sha2 hash.

        Args:
            resources: list of string hashes.
        Returns:
            a file download
        """
        api_name = 'virustotal-file-download'
        api_endpoint = 'file/download'
        return self._extract_all_responses(resources, api_endpoint, api_name)

    @MultiRequest.error_handling
    def get_file_network_traffic(self, resources):
        """Retrieves a report about the network traffic of a md5, sha1, and/or sha2 hash of
           file, when it is executed.

        Args:
            resources: list of string hashes.
        """
        api_name = 'virustotal-file-network-traffic'
        api_endpoint = 'file/network-traffic'
        return self._extract_all_responses(resources, api_endpoint, api_name)

    @MultiRequest.error_handling
    def get_domain_reports(self, domains):
        """Retrieves the most recent VT info for a set of domains.

        Args:
            domains: list of string domains.
        Returns:
            A dict with the domain as key and the VT report as value.
        """
        api_name = 'virustotal-domain-reports'

        (all_responses, domains) = self._bulk_cache_lookup(api_name, domains)
        responses = self._request_reports("domain", domains, 'domain/report')

        for domain, response in zip(domains, responses):
            if self._cache:
                self._cache.cache_value(api_name, domain, response)
            all_responses[domain] = response

        return all_responses

    @MultiRequest.error_handling
    def get_url_distribution(self, params=None):
        """Retrieves a live feed with the latest URLs submitted to VT.

        Args:
            resources: a dictionary with name and value for optional arguments
        Returns:
            A dict with the VT report.
        """
        params = params or {}
        all_responses = {}
        api_name = 'virustotal-url-distribution'

        response_chunks = self._request_reports(list(params.keys()), list(params.values()), 'url/distribution')
        self._extract_response_chunks(all_responses, response_chunks, api_name)

        return all_responses

    @MultiRequest.error_handling
    def get_file_distribution(self, params=None):
        """Retrieves a live feed with the latest hashes submitted to VT.

        Args:
            params: a dictionary with name and values for optional arguments,
            such as: before (timestampe), after (timestamp), reports (boolean),
            limit (retrieve limit file items).
            Example: 'reports': 'true'
        Returns:
            A dict with the VT report.
        """
        params = params or {}
        all_responses = {}
        api_name = 'virustotal-file-distribution'

        response_chunks = self._request_reports(list(params.keys()), list(params.values()), 'file/distribution')
        self._extract_response_chunks(all_responses, response_chunks, api_name)

        return all_responses

    @MultiRequest.error_handling
    def get_url_reports(self, resources):
        """Retrieves a scan report on a given URL.

        Args:
            resources: list of URLs.
        Returns:
            A dict with the URL as key and the VT report as value.
        """
        api_name = 'virustotal-url-reports'

        (all_responses, resources) = self._bulk_cache_lookup(api_name, resources)
        resource_chunks = self._prepare_resource_chunks(resources, '\n')
        response_chunks = self._request_reports("resource", resource_chunks, 'url/report')
        self._extract_response_chunks(all_responses, response_chunks, api_name)

        return all_responses

    @MultiRequest.error_handling
    def get_ip_reports(self, ips):
        """Retrieves the most recent VT info for a set of ips.

        Args:
            ips: list of IPs.
        Returns:
            A dict with the IP as key and the VT report as value.
        """
        api_name = 'virustotal-ip-address-reports'

        (all_responses, ips) = self._bulk_cache_lookup(api_name, ips)
        responses = self._request_reports("ip", ips, 'ip-address/report')

        for ip, response in zip(ips, responses):
            if self._cache:
                self._cache.cache_value(api_name, ip, response)
            all_responses[ip] = response

        return all_responses

    @MultiRequest.error_handling
    def get_file_search(self, query):
        """Performs advanced search on samples, matching certain binary/
           metadata/detection criteria.
           Possible queries: file size, file type, first or last submission to
            VT, number of positives, bynary content, etc.

        Args:
            query: dictionary with search arguments
            Example: 'query': 'type:peexe size:90kb+ positives:5+ behaviour:"taskkill"'
        Returns:
            A dict with the VT report.
        """
        api_name = 'virustotal-file-search'

        (all_responses, query) = self._bulk_cache_lookup(api_name, query)
        response_chunks = self._request_reports("query", query, 'file/search')
        self._extract_response_chunks(all_responses, response_chunks, api_name)

        return all_responses

    @MultiRequest.error_handling
    def get_file_clusters(self, date):
        """Retrieves file similarity clusters for a given time frame.

        Args:
            date: the specific date for which we want the clustering details.
            Example: 'date': '2013-09-10'
        Returns:
            A dict with the VT report.
        """
        api_name = 'virustotal-file-clusters'

        (all_responses, resources) = self._bulk_cache_lookup(api_name, date)
        response = self._request_reports("date", date, 'file/clusters')
        self._extract_response_chunks(all_responses, response, api_name)

        return all_responses

    def _bulk_cache_lookup(self, api_name, keys):
        """Performes a bulk cache lookup and returns a tuple with the results
        found and the keys missing in the cache. If cached is not configured
        it will return an empty dictionary of found results and the initial
        list of keys.

        Args:
            api_name: a string name of the API.
            keys: an enumerable of string keys.
        Returns:
            A tuple: (responses found, missing keys).
        """
        if self._cache:
            responses = self._cache.bulk_lookup(api_name, keys)
            missing_keys = [key for key in keys if key not in responses.keys()]
            return (responses, missing_keys)

        return ({}, keys)

    def _prepare_resource_chunks(self, resources, resource_delim=','):
        """As in some VirusTotal API methods the call can be made for multiple
        resources at once this method prepares a list of concatenated resources
        according to the maximum number of resources per requests.

        Args:
            resources: a list of the resources.
            resource_delim: a string used to separate the resources.
              Default value is a comma.
        Returns:
            A list of the concatenated resources.
        """
        return [self._prepare_resource_chunk(resources, resource_delim, pos)
                for pos in range(0, len(resources), self._resources_per_req)]

    def _prepare_resource_chunk(self, resources, resource_delim, pos):
        return resource_delim.join(
            resources[pos:pos + self._resources_per_req])

    def _request_reports(self, resource_param_name, resources, endpoint_name):
        """Sends multiples requests for the resources to a particular endpoint.

        Args:
            resource_param_name: a string name of the resource parameter.
            resources: list of of the resources.
            endpoint_name: VirusTotal endpoint URL suffix.
        Returns:
            A list of the responses.
        """
        params = [{resource_param_name: resource, 'apikey': self._api_key} for resource in resources]
        return self._requests.multi_get(self.BASE_DOMAIN + endpoint_name, query_params=params)

    def _extract_response_chunks(self, all_responses, response_chunks, api_name):
        """Extracts and caches the responses from the response chunks in case
        of the responses for the requests containing multiple concatenated
        resources. Extracted responses are added to the already cached
        responses passed in the all_responses parameter.

        Args:
            all_responses: a list containing already cached responses.
            response_chunks: a list with response chunks.
            api_name: a string name of the API.
        """
        for response_chunk in response_chunks:
            if not isinstance(response_chunk, list):
                response_chunk = [response_chunk]
            for response in response_chunk:
                if not response:
                    continue

                if self._cache:
                    self._cache.cache_value(api_name, response['resource'], response)
                all_responses[response['resource']] = response
