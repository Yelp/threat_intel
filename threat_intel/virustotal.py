# -*- coding: utf-8 -*-
#
# VirusTotalApi makes calls to the VirusTotal API.
#
from six.moves import range

from threat_intel.util.api_cache import ApiCache
from threat_intel.util.http import MultiRequest


class VirusTotalApi(object):
    BASE_DOMAIN = u'https://www.virustotal.com/api/v3/'

    def __init__(self, api_key, cache_file_name=None, update_cache=True, req_timeout=None):
        """Establishes basic HTTP params and loads a cache.

        Args:
            api_key: VirusTotal API key
            cache_file_name: String file name of cache.
            update_cache: Determines whether cache should be written out back to the disk when closing it.
                          Default is `True`.
            req_timeout: Maximum number of seconds to wait without reading a response byte before deciding an error has occurred.
                         Default is None.
        """
        self._requests = MultiRequest(req_timeout=req_timeout, default_headers={'x-apikey': api_key})

        # Create an ApiCache if instructed to
        self._cache = ApiCache(cache_file_name, update_cache) if cache_file_name else None

    @MultiRequest.error_handling
    def get_file_reports(self, file_hash_list):
        """Retrieves the most recent reports for a set of md5, sha1, and/or sha2 hashes.

        Args:
            file_hash_list: list of string hashes.
        Returns:
            A dict with the hash as key and the VT report as value.
        """
        api_name = 'virustotal-file-reports'
        api_endpoint = 'files/{}'

        all_responses, file_hash_list = self._bulk_cache_lookup(api_name, file_hash_list)
        response_chunks = self._request_reports(file_hash_list, api_endpoint)
        self._extract_response_chunks(all_responses, response_chunks, api_name)

        return all_responses

    @MultiRequest.error_handling
    def get_file_behaviour(self, file_hash_list):
        """Retrieves a report about the behaviour of a md5, sha1, and/or sha2 hash of
        a file when executed in a sandboxed environment (Cuckoo sandbox).

        Args:
            file_hash_list: list of string hashes.
        """
        api_name = 'virustotal-file-behaviour'
        api_endpoint = 'files/{}/behaviours'

        all_responses, file_hash_list = self._bulk_cache_lookup(api_name, file_hash_list)
        response_chunks = self._request_reports(file_hash_list, api_endpoint)
        self._extract_response_chunks(all_responses, response_chunks, api_name)

        return all_responses

    @MultiRequest.error_handling
    def get_file_download(self, file_hash_list):
        """Retrieves a file from its a md5, sha1, and/or sha2 hash.

        Args:
            file_hash_list: list of string hashes.
        Returns:
            a base64encoded string of the file
        """
        api_name = 'virustotal-file-download'
        api_endpoint = 'files/{}/download'
        return self._extract_all_responses(file_hash_list, api_endpoint, api_name, file_download=True)

    @MultiRequest.error_handling
    def get_file_contacted_domains(self, file_hash_list):
        """Retrieves a report about the contacted domains of a md5, sha1, and/or sha2 hash of
           file, when it is executed.

        Args:
            file_hash_list: list of string hashes.
        """
        api_name = 'virustotal-file-contacted-domains'
        api_endpoint = 'files/{}/contacted_domains'

        return self._extract_all_responses(file_hash_list, api_endpoint, api_name)

    @MultiRequest.error_handling
    def get_file_contacted_ips(self, file_hash_list):
        """Retrieves a report about the contacted ip addresses of a md5, sha1,
           and/or sha2 hash of file, when it is executed.

        Args:
            resources: list of string hashes.
        """
        api_name = 'virustotal-file-contacted-ips'
        api_endpoint = 'files/{}/contacted_ips'

        return self._extract_all_responses(file_hash_list, api_endpoint, api_name)

    @MultiRequest.error_handling
    def get_file_contacted_urls(self, file_hash_list):
        """Retrieves a report about the contacted urls of a md5, sha1,
           and/or sha2 hash of file, when it is executed.

        Args:
            file_hash_list: list of string hashes.
        """
        api_name = 'virustotal-file-contacted-urls'
        api_endpoint = 'files/{}/contacted_urls'

        return self._extract_all_responses(file_hash_list, api_endpoint, api_name)

    @MultiRequest.error_handling
    def get_file_itw_urls(self, file_hash_list):
        """Retrieves a report about the in the wild URLs from where the file
           with the hash has been downloaded.

        Args:
            file_hash_list: list of string hashes.
        """
        api_name = 'virustotal-file-itw-urls'
        api_endpoint = 'files/{}/itw_urls'

        return self._extract_all_responses(file_hash_list, api_endpoint, api_name)

    @MultiRequest.error_handling
    def get_domain_communicating_files(self, domain_list):
        """Retrieves a report about the files that communicate with this internet domain.

        Args:
            domain_list: list of string domains.
        """
        api_name = 'virustotal-domain-communicating-files'
        api_endpoint = 'domains/{}/communicating_files'

        return self._extract_all_responses(domain_list, api_endpoint, api_name)

    @MultiRequest.error_handling
    def get_domain_referrer_files(self, domain_list):
        """Retrieves a report about the files containing the internet domain.

        Args:
            domain_list: list of string domains.
        """
        api_name = 'virustotal-domain-referrer-files'
        api_endpoint = 'domains/{}/referrer_files'

        return self._extract_all_responses(domain_list, api_endpoint, api_name)

    @MultiRequest.error_handling
    def get_domain_reports(self, domain_list):
        """Retrieves the most recent VT info for a set of domains.

        Args:
            domain_list: list of string domains.
        Returns:
            A dict with the domain as key and the VT report as value.
        """
        api_name = 'virustotal-domain-reports'

        (all_responses, domain_list) = self._bulk_cache_lookup(api_name, domain_list)
        responses = self._request_reports(domain_list, 'domains/{}')

        for domain, response in zip(domain_list, responses):
            if self._cache:
                self._cache.cache_value(api_name, domain, response)
            all_responses[domain] = response

        return all_responses

    @MultiRequest.error_handling
    def get_feeds_url(self, time_frame):
        """Retrieves a live feed with the latest URLs submitted to VT.

        Args:
            time_frame: a list of timeframe strings in date format YYYYMMDDhhmm.
        Returns:
            A base64 encoded bzip2 compressed UTF-8 text file contains one JSON structure per line.
        """
        api_name = 'virustotal-url-distribution'
        all_responses = {}

        response = self._request_reports(time_frame, 'feeds/urls/{}', file_download=True)
        self._extract_response_chunks(all_responses, response, api_name)

        return all_responses

    @MultiRequest.error_handling
    def get_file_distribution(self, time_frame):
        """Retrieves a live feed with the latest hashes submitted to VT.

        Args:
            time_frame: A list of strings in format YYYYMMDDhhmm.
        Returns:
            A dict with the VT report.
        """
        all_responses = {}
        api_name = 'virustotal-file-distribution'

        response = self._request_reports(time_frame, 'feeds/files/{}')
        self._extract_response_chunks(all_responses, response, api_name)

        return all_responses

    @MultiRequest.error_handling
    def get_url_reports(self, url_hash_list):
        """Retrieves a scan report on a given URL.

        Args:
            url_hash_list: list of sha256 hashed urls.
        Returns:
            A dict with the URL hash as key and the VT report as value.
        """
        api_name = 'virustotal-url-reports'
        api_endpoint = 'urls/{}'

        return self._extract_all_responses(url_hash_list, api_endpoint, api_name)

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
        responses = self._request_reports(ips, 'ip_addresses/{}')

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
        api_endpoint = 'intelligence/search?query={}'

        return self._extract_all_responses(query, api_endpoint, api_name)

    @MultiRequest.error_handling
    def get_file_clusters(self, time_frame):
        """Retrieves file similarity clusters for a given time frame.

        Args:
            time_frame: a list of time frames for which we want the clustering details in YYYYMMDDhhmm format.
        Returns:
            A dict with the VT report.
        """
        api_name = 'virustotal-file-clusters'
        api_endpoint = 'feeds/file-behaviours/{}'

        return self._extract_all_responses(time_frame, api_endpoint, api_name)


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

    def _request_reports(self, ids, endpoint_name, file_download=False):
        """Sends multiples requests for the resources to a particular endpoint.

        Args:
            ids: list of the hash identifying the file.
            endpoint_name: VirusTotal endpoint URL suffix.
            file_download: boolean, whether a file download is expected
        Returns:
            A list of the responses.
        """
        urls = ['{}{}'.format(self.BASE_DOMAIN, endpoint_name.format(id)) for id in ids]
        return self._requests.multi_get(urls, file_download=file_download) if urls else []


    def _extract_cache_id(self, response):
        """Extracts the object hash from the response to be used to
           uniquely identify the result.

        Args:
            response: response object.
        Returns:
            A hash that uniquely identities the result.
        """

        cache_id = None
        if isinstance(response['data'], list):
            if response['data']:
                # gets the first data items' id
                cache_id = response['data'][0]['id']
        else:
            cache_id = response['data']['id']
        # sandbox id output has an underscore as the separator
        if cache_id and '_' in cache_id:
            cache_id = cache_id.split('_')[0]
        return cache_id

    def _extract_all_responses(self, resources, api_endpoint, api_name, file_download=False):
        """ Aux function to extract all the API endpoint responses.

        Args:
            resources: list of string hashes.
            api_endpoint: endpoint path
            api_name: endpoint name
        Returns:
            A dict with the hash as key and the VT report as value.
        """
        all_responses, resources = self._bulk_cache_lookup(api_name, resources)
        response_chunks = self._request_reports(resources, api_endpoint, file_download)
        self._extract_response_chunks(all_responses, response_chunks, api_name)

        return all_responses

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

                cache_id = self._extract_cache_id(response)
                if cache_id:
                    if self._cache:
                        self._cache.cache_value(api_name, cache_id, response)
                    all_responses[cache_id] = response
