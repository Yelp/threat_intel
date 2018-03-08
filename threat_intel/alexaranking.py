# -*- coding: utf-8 -*-
#
# AlexaRankingsAPI makes calls to the Alexa Ranking API
#
from threat_intel.util.api_cache import ApiCache
from threat_intel.util.http import MultiRequest
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import ParseError


class AlexaRankingApi(object):

    BASE_URL = u'https://data.alexa.com/data?cli=10'

    def __init__(self, resources_per_req=10, cache_file_name=None,
                 update_cache=True, req_timeout=None):
        """Establishes basic HTTP params and loads a cache.

        Args:
            resources_per_req: Maximum number of resources (hashes, URLs)
                to be send in a single request
            cache_file_name: String file name of cache.
            update_cache: Determines whether cache should be written out
                          back to the disk when closing it.
                          Default is `True`.
            req_timeout: Maximum number of seconds to wait without reading
                         a response byte before deciding an error has occurred.
                         Default is None.
        """
        self._resources_per_req = resources_per_req
        self._requests = MultiRequest(req_timeout=req_timeout)

        # Create an ApiCache if instructed to
        self._cache = ApiCache(cache_file_name,
                               update_cache) if cache_file_name else None

    @MultiRequest.error_handling
    def get_alexa_rankings(self, domains):
        """Retrieves the most recent VT info for a set of domains.

        Args:
            domains: list of string domains.
        Returns:
            A dict with the domain as key and the VT report as value.
        """
        api_name = 'alexa_rankings'

        (all_responses, domains) = self._bulk_cache_lookup(api_name, domains)
        responses = self._request_reports(domains)

        for domain, response in zip(domains, responses):
            xml_response = self._extract_response_xml(domain, response)
            if self._cache:
                self._cache.cache_value(api_name, domain, response)
            all_responses[domain] = xml_response

        return all_responses

    def _request_reports(self, domains):
        """Sends multiples requests for the resources to a particular endpoint.

        Args:
            resource_param_name: a string name of the resource parameter.
            resources: list of of the resources.
            endpoint_name: AlexaRankingApi endpoint URL suffix.
        Returns:
            A list of the responses.
        """
        params = [{'url': domain} for domain in domains]
        responses = self._requests.multi_get(
            self.BASE_URL, query_params=params, to_json=False)
        return responses

    def _extract_response_xml(self, domain, response):
        """Extract XML content of an HTTP response into dictionary format.

        Args:
            response: HTML Response objects
        Returns:
            A dictionary: {alexa-ranking key : alexa-ranking value}.
        """
        attributes = {}
        alexa_keys = {'POPULARITY': 'TEXT', 'REACH': 'RANK', 'RANK': 'DELTA'}
        try:
            xml_root = ET.fromstring(response._content)
            for xml_child in xml_root.findall('SD//'):
                if xml_child.tag in alexa_keys and \
                        alexa_keys[xml_child.tag] in xml_child.attrib:
                    attributes[xml_child.tag.lower(
                    )] = xml_child.attrib[alexa_keys[xml_child.tag]]
        except ParseError:
            # Skip ill-formatted XML and return no Alexa attributes
            pass
        attributes['domain'] = domain
        return {'attributes': attributes}

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
