# -*- coding: utf-8 -*-
#
# InvestigateApi makes calls to the OpenDNS Investigate API.
#
import simplejson

from threat_intel.util.api_cache import ApiCache
from threat_intel.util.error_messages import write_error_message
from threat_intel.util.error_messages import write_exception
from threat_intel.util.http import MultiRequest


def _cached_by_domain(api_name):
    """A caching wrapper for functions that take a list of domains as parameters."""

    def wrapped(func):
        def decorated(self, domains):
            if not self._cache:
                return func(self, domains)

            all_responses = {}
            all_responses = self._cache.bulk_lookup(api_name, domains)
            domains = list(set(domains) - set(all_responses))

            if domains:
                response = func(self, domains)

                # TODO better exception
                if not response:
                    raise Exception('dang')

                for domain in response:
                    self._cache.cache_value(api_name, domain, response[domain])
                    all_responses[domain] = response[domain]

            return all_responses
        return decorated
    return wrapped


class InvestigateApi(object):

    """Calls the OpenDNS investigate API.

    Applies rate limits and issues parallel requests.
    """

    BASE_URL = u'https://investigate.api.opendns.com/'

    def __init__(self, api_key, cache_file_name=None):
        auth_header = {'Authorization': 'Bearer {0}'.format(api_key)}
        self._requests = MultiRequest(default_headers=auth_header, max_requests=12, rate_limit=30)

        # Create an ApiCache if instructed to
        self._cache = ApiCache(cache_file_name) if cache_file_name else None

    @classmethod
    def _to_url(cls, url_path):
        try:
            return u'{0}{1}'.format(cls.BASE_URL, url_path)
        except Exception as e:
            write_error_message(url_path)
            write_exception(e)
            raise e

    @classmethod
    def _to_urls(cls, fmt_url_path, url_path_args):
        url_paths = []
        for path_arg in url_path_args:
            try:
                url_paths.append(fmt_url_path.format(path_arg))
            except Exception as e:
                write_error_message(path_arg)
                write_exception(e)
                raise e

        return [cls._to_url(url_path) for url_path in url_paths]

    @MultiRequest.error_handling
    @_cached_by_domain(api_name='opendns-categorization')
    def categorization(self, domains):
        """Calls categorization end point and adds an 'is_suspicious' key to each response.

        Args:
            domains: An enumerable of domains
        Returns:
            A dict of {domain: categorization_result}
        """
        url_path = u'domains/categorization/?showLabels'
        response = self._requests.multi_post(self._to_url(url_path), data=simplejson.dumps(domains))
        return response[0]

    @MultiRequest.error_handling
    @_cached_by_domain(api_name='opendns-domain_score')
    def domain_score(self, domains):
        url_path = 'domains/score/'
        response = self._requests.multi_post(self._to_url(url_path), data=simplejson.dumps(domains))
        return response[0]

    @MultiRequest.error_handling
    def _multi_get(self, cache_api_name, fmt_url_path, url_params):
        """Makes multiple GETs to an OpenDNS endpoint.

        Args:
            cache_api_name: string api_name for caching
            fmt_url_path: format string for building URL paths
            url_params: An enumerable of strings used in building URLs
        Returns:
            A dict of {url_param: api_result}
        """
        all_responses = {}

        if self._cache:
            all_responses = self._cache.bulk_lookup(cache_api_name, url_params)
            url_params = [key for key in url_params if key not in all_responses.keys()]

        if len(url_params):
            urls = self._to_urls(fmt_url_path, url_params)
            responses = self._requests.multi_get(urls)
            responses = dict(zip(url_params, responses))
            for url_param in responses.keys():
                if self._cache:
                    self._cache.cache_value(cache_api_name, url_param, responses[url_param])
                all_responses[url_param] = responses[url_param]

        return all_responses

    def security(self, domains):
        """Calls security end point and adds an 'is_suspicious' key to each response.

        Args:
            domains: An enumerable of strings
        Returns:
            A dict of {domain: security_result}
        """
        api_name = 'opendns-security'
        fmt_url_path = u'security/name/{0}.json'
        return self._multi_get(api_name, fmt_url_path, domains)

    def cooccurrences(self, domains):
        """Get the domains related to input domains.

        Args:
            domains: an enumerable of strings domain names
        Returns:
            An enumerable of string domain names
        """
        api_name = 'opendns-cooccurrences'
        fmt_url_path = u'recommendations/name/{0}.json'
        return self._multi_get(api_name, fmt_url_path, domains)

    def domain_tag(self, domains):
        """Get the data range when a domain is part of OpenDNS block list.

        Args:
            domains: an enumerable of strings domain names
        Returns:
            An enumerable of string with period, category, and url
        """
        api_name = 'opendns-domain_tag'
        fmt_url_path = u'domains/name/{0}/latest_tags'
        return self._multi_get(api_name, fmt_url_path, domains)

    def related_domains(self, domains):
        """Get list of domain names that have been seen requested around the
        same time (up to 60 seconds before or after) to the given domain name.

        Args:
            domains: an enumerable of strings domain names
        Returns:
            An enumerable of [domain name, scores]
        """
        api_name = 'opendns-related_domains'
        fmt_url_path = u'links/name/{0}.json'
        return self._multi_get(api_name, fmt_url_path, domains)

    def rr_history(self, ips):
        """Get the domains related to input ips.

        Args:
            ips: an enumerable of strings as ips
        Returns:
            An enumerable of resource records and features
        """
        api_name = 'opendns-rr_history'
        fmt_url_path = u'dnsdb/ip/a/{0}.json'
        return self._multi_get(api_name, fmt_url_path, ips)

    def dns_rr(self, ips):
        """Get the domains related to input domains.

        Args:
            domains: an enumerable of strings as domains
        Returns:
            An enumerable of resource records and features
        """
        api_name = 'opendns-dns_rr'
        fmt_url_path = u'dnsdb/name/a/{0}.json'
        return self._multi_get(api_name, fmt_url_path, ips)

    def latest_malicious(self, ips):
        """Get the a list of malicious domains related to input ips.

        Args:
            ips: an enumerable of strings as ips
        Returns:
            An enumerable of strings for the malicious domains
        """
        api_name = 'opendns-latest_malicious'
        fmt_url_path = u'ips/{0}/latest_domains'
        return self._multi_get(api_name, fmt_url_path, ips)
