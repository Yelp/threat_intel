# -*- coding: utf-8 -*-
#
# NetApiRankingApi makes calls to the NetAPI JSON API (domain rank in the NetAPI Top 1M)
#
from threat_intel.util.api_cache import ApiCache
from threat_intel.util.http import MultiRequest


class NetApiRankingApi(object):

    BASE_URL = u'https://netapi.com/api-json/'

    def __init__(self, api_token=None, cache_file_name=None, update_cache=True, req_timeout=None, max_requests=1, rate_limit=1):
        """Establishes basic HTTP params and loads a cache.

        Args:
            api_token: Optional NetAPI API token. The domain-rank method is free and needs no token
                       (30 requests a minute, 1,000 a day per IP); the token of a free NetAPI account
                       raises that to 60 a minute and 5,000 a day.
            cache_file_name: String file name of cache.
            update_cache: Determines whether cache should be written out back to the disk when closing it.
                          Default is `True`.
            req_timeout: Maximum number of seconds to wait without reading a response byte before deciding
                         an error has occurred. Default is None.
            max_requests: Maximum number of requests to issue at once. Default is 1.
            rate_limit: Maximum number of requests to issue per second; must not be lower than max_requests.
                        Default is 1, i.e. one request per second.
        """
        default_headers = {'Authorization': u'Bearer {0}'.format(api_token)} if api_token else None
        self._requests = MultiRequest(
            default_headers=default_headers, max_requests=max_requests, rate_limit=rate_limit, req_timeout=req_timeout,
        )

        # Create an ApiCache if instructed to
        self._cache = ApiCache(cache_file_name, update_cache) if cache_file_name else None

    @MultiRequest.error_handling
    def get_domain_rankings(self, domains):
        """Retrieves the position of each domain in the NetAPI Top 1M.

        Args:
            domains: list of string domains.
        Returns:
            A dict with the domain as key and the NetAPI domain-rank report as value. A domain outside the
            Top 1M gets a report with `in_top_1m` False and `rank` None; a failed request gives a report with
            only the `domain` key.
        """
        api_name = 'netapi_domain_rank'

        (all_responses, domains) = self._bulk_cache_lookup(api_name, domains)
        responses = self._request_reports(domains) if domains else []

        for domain, response in zip(domains, responses):
            report = self._extract_report(domain, response)
            if self._cache:
                self._cache.cache_value(api_name, domain, report)
            all_responses[domain] = report

        return all_responses

    def _request_reports(self, domains):
        """Sends one request per domain to the domain-rank method.

        Args:
            domains: list of string domains.
        Returns:
            A list of the responses (dicts, or None where the request failed).
        """
        params = [{'method': 'domain-rank', 'domain': domain} for domain in domains]
        return self._requests.multi_get(self.BASE_URL, query_params=params)

    def _extract_report(self, domain, response):
        """Keeps the ranking fields of a domain-rank answer.

        Args:
            domain: the string domain the request was made for.
            response: the decoded JSON answer, or None.
        Returns:
            A dictionary with the ranking fields of the answer plus the requested domain.
        """
        report = {'domain': domain}
        if isinstance(response, dict) and 'error' not in response:
            for key in ('in_top_1m', 'rank', 'rank_in_tld', 'tld', 'tld_sites_in_top_1m', 'snapshot_date'):
                if key in response:
                    report[key] = response[key]
        return report

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
