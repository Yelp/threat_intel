# -*- coding: utf-8 -*-
#
# Utilities for dealing with HTTP requests
#
# RateLimiter helps to only make a certain number of calls per second.
# MultiRequest wraps grequests and issues multiple requests at once with an easy to use interface.
# SSLAdapter helps force use of the highest possible version of TLS.
#
import logging
from six.moves import range
import ssl
import time
from collections import namedtuple
from collections import OrderedDict

import grequests
from requests import Session
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

from threat_intel.exceptions import InvalidRequestError
from threat_intel.util.error_messages import write_error_message
from threat_intel.util.error_messages import write_exception


class SSLAdapter(HTTPAdapter):

    """Attempt to use the highest possible TLS version for HTTPS connections.

    By explictly controlling which TLS version is used when connecting, avoid the client offering only SSLv2 or SSLv3.

    While it may seem counter intuitive, the best version specifier to pass is `ssl.PROTOCOL_SSLv23`
    This will actually choose the highest available protocol compatible with both client and server.
    For details see the documentation for `ssl.wrap_socket` https://docs.python.org/2/library/ssl.html#socket-creation

    To use this class, mount it to a `requests.Session` and then make HTTPS using the session object.

    .. code-block:: python
        # Mount an SSLAdapter in a Session
        session = requests.Session()
        session.mount('https://', SSLAdapter())

        # Make a requests call through the session
        session.get('https://api.github.com/events')

        # Make a grequests call through the session
        grequests.get('https://api.github.com/events', session=session)

    """

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        """Called to initialize the HTTPAdapter when no proxy is used."""
        pool_kwargs['ssl_version'] = ssl.PROTOCOL_SSLv23
        return super(SSLAdapter, self).init_poolmanager(connections, maxsize, block, **pool_kwargs)

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        """Called to initialize the HTTPAdapter when a proxy is used."""
        proxy_kwargs['ssl_version'] = ssl.PROTOCOL_SSLv23
        return super(SSLAdapter, self).proxy_manager_for(proxy, **proxy_kwargs)


class RateLimiter(object):

    """Limits how many calls can be made per second"""

    CallRecord = namedtuple('CallRecord', ['time', 'num_calls'])

    def __init__(self, calls_per_sec):
        self._max_calls_per_second = calls_per_sec
        self._call_times = []
        self._outstanding_calls = 0

    def make_calls(self, num_calls=1):
        """Adds appropriate sleep to avoid making too many calls.

        Args:
            num_calls: int the number of calls which will be made
        """
        self._cull()
        while self._outstanding_calls + num_calls > self._max_calls_per_second:
            time.sleep(0)  # yield
            self._cull()

        self._call_times.append(self.CallRecord(time=time.time(), num_calls=num_calls))
        self._outstanding_calls += num_calls

    def _cull(self):
        """Remove calls more than 1 second old from the queue."""
        right_now = time.time()

        cull_from = -1
        for index in range(len(self._call_times)):
            if right_now - self._call_times[index].time >= 1.0:
                cull_from = index
                self._outstanding_calls -= self._call_times[index].num_calls
            else:
                break

        if cull_from > -1:
            self._call_times = self._call_times[cull_from + 1:]

class AvailabilityLimiter(object):

    """Limits the total number of requests issued for a session."""

    def __init__(self, total_retries):
        """ Wrapper object for managing total session retry limit.

        Args:
                total_retries: Total request attempts to be made per sesssion. 
                               This is shared between all request objects.
        """
        self.total_retries = total_retries

    def map_with_retries(self, requests, responses_for_requests, *args, **kwargs):
        """Wraps around grequests.map to provide session-based retry functionality

        :param requests: A collection of Request objects.
        :param responses_for_requests: Dictionary mapping of requests to responses
        :param max_retries: The maximum number of retries to perform per session
        :param exception_handler: Callback function, called when exception occured. Params: Request, Exception
        :param args: Additional arguments to pass into a retry mapping call
        :param kwargs: Keyword arguments passed into the grequests wrapper, e.g. exception_handler


        """
        _exception_handler = kwargs.pop('exception_handler', None)
        retries = []


        def exception_handler(request, exception, *args, **kwargs):
            if self.total_retries > 0:
                self.total_retries -= 1
                retries.append(request)
            if _exception_handler:
                return _exception_handler(request, exception, *args, **kwargs)

        responses = grequests.map(requests, exception_handler=exception_handler, *args, **kwargs)

        for request, response in zip(requests, responses):
            if response is not None and response.status_code == 403:
                logging.debug('Request was received with a 403 response status code.')
                raise InvalidRequestError('Access forbidden')
            if response:
                responses_for_requests[request] = response

        # Recursively retry failed requests with the modified total retry count
        if retries:
            self.map_with_retries(retries, responses_for_requests,
                 *args, exception_handler=_exception_handler, **kwargs)

class MultiRequest(object):

    """Wraps grequests to make simultaneous HTTP requests.

    Can use a RateLimiter to limit # of outstanding requests.
    Can also use AvailabilityLimiter to limit total # of request issuance threshold.
    `multi_get` and `multi_post` try to be smart about how many requests to issue:

    * One url & one param - One request will be made.
    * Multiple url & one query param - Multiple requests will be made, with differing urls and the same query param.
    * Multiple url & multiple query params - Multiple requests will be made, with the same url and differing query params.
    """

    _VERB_GET = 'GET'
    _VERB_POST = 'POST'

    def __init__(self, default_headers=None, max_requests=20,
            rate_limit=0, req_timeout=None, max_retry=10, total_retry=100):
        """Create the MultiRequest.

        Args:
            default_headers - A dict of headers which will be added to every request
            max_requests - Maximum number of requests to issue at once
            rate_limit - Maximum number of requests to issue per second
            req_timeout - Maximum number of seconds to wait without reading a response byte before deciding an error has occurred
            max_retry - The total number of attempts to retry a single batch of requests
            total_retry - The total number of request retries that can be made through the entire session
        Note there is a difference between `max_retry` and `total_retry`:
            - `max_retry` refers to how many times a batch of requests will be re-issued collectively
            - `total_retry` refers to a limit on the total number of outstanding requests made
            Once the latter is exhausted, no failed request within the whole session will be retried.
        """
        self._default_headers = default_headers
        self._max_requests = max_requests
        self._req_timeout = req_timeout or 25.0
        self._max_retry = max_retry
        self._rate_limiter = RateLimiter(rate_limit) if rate_limit else None
        self._availability_limiter = AvailabilityLimiter(total_retry) if total_retry else None
        self._session = Session()
        retries = Retry(total=0, status_forcelist=[500, 502, 503, 504], raise_on_status=True)
        self._session.mount('https://', SSLAdapter(max_retries=retries, pool_maxsize=max(10, max_requests)))

    def multi_get(self, urls, query_params=None, to_json=True):
        """Issue multiple GET requests.

        Args:
            urls - A string URL or list of string URLs
            query_params - None, a dict, or a list of dicts representing the query params
            to_json - A boolean, should the responses be returned as JSON blobs
        Returns:
            a list of dicts if to_json is set of grequest.response otherwise.
        Raises:
            InvalidRequestError - Can not decide how many requests to issue.
        """
        return self._multi_request(MultiRequest._VERB_GET, urls, query_params, None, to_json=to_json)

    def multi_post(self, urls, query_params=None, data=None, to_json=True, send_as_file=False):
        """Issue multiple POST requests.

        Args:
            urls - A string URL or list of string URLs
            query_params - None, a dict, or a list of dicts representing the query params
            data - None, a dict or string, or a list of dicts and strings representing the data body.
            to_json - A boolean, should the responses be returned as JSON blobs
            send_as_file - A boolean, should the data be sent as a file.
        Returns:
            a list of dicts if to_json is set of grequest.response otherwise.
        Raises:
            InvalidRequestError - Can not decide how many requests to issue.
        """
        return self._multi_request(MultiRequest._VERB_POST, urls, query_params, data, to_json=to_json, send_as_file=send_as_file)

    def _create_request(self, verb, url, query_params=None, data=None, send_as_file=False):
        """Helper method to create a single `grequests.post` or `grequests.get`.

        Args:
            verb - MultiRequest._VERB_POST or MultiRequest._VERB_GET
            url - A string URL
            query_params - None or a dict
            data - None or a string or a dict
            send_as_file - A boolean, should the data be sent as a file.
        Returns:
            requests.PreparedRequest
        Raises:
            InvalidRequestError - if an invalid verb is passed in.
        """

        # Prepare a set of kwargs to make it easier to avoid missing default params.
        kwargs = {
            'headers': self._default_headers,
            'params': query_params,
            'timeout': self._req_timeout,
            'session': self._session
        }

        if MultiRequest._VERB_POST == verb:
            if not send_as_file:
                return grequests.post(url, data=data, **kwargs)
            else:
                return grequests.post(url, files={'file': data}, **kwargs)
        elif MultiRequest._VERB_GET == verb:
            return grequests.get(url, data=data, **kwargs)
        else:
            raise InvalidRequestError('Invalid verb {0}'.format(verb))

    def _zip_request_params(self, urls, query_params, data):
        """Massages inputs and returns a list of 3-tuples zipping them up.

        This is all the smarts behind deciding how many requests to issue.
        It's fine for an input to have 0, 1, or a list of values.
        If there are two inputs each with a list of values, the cardinality of those lists much match.

        Args:
            urls - 1 string URL or a list of URLs
            query_params - None, 1 dict, or a list of dicts
            data - None, 1 dict or string, or a list of dicts or strings
        Returns:
            A list of 3-tuples (url, query_param, data)
        Raises:
            InvalidRequestError - if cardinality of lists does not match
        """

        # Everybody gets to be a list
        if not isinstance(urls, list):
            urls = [urls]
        if not isinstance(query_params, list):
            query_params = [query_params]
        if not isinstance(data, list):
            data = [data]

        # Counts must not mismatch
        url_count = len(urls)
        query_param_count = len(query_params)
        data_count = len(data)

        max_count = max(url_count, query_param_count, data_count)

        if ((url_count < max_count and url_count > 1) or
                (query_param_count < max_count and query_param_count > 1) or
                (data_count < max_count and data_count > 1)):
            raise InvalidRequestError('Mismatched parameter count url_count:{0} query_param_count:{1} data_count:{2} max_count:{3}',
                                      url_count, query_param_count, data_count, max_count)

        # Pad out lists
        if url_count < max_count:
            urls = urls * max_count
        if query_param_count < max_count:
            query_params = query_params * max_count
        if data_count < max_count:
            data = data * max_count

        return list(zip(urls, query_params, data))

    def _handle_exception(self, request, exception):
        """Handles grequests exception (timeout, etc.).

        Args:
            request - A request that caused the exception
            exception - An exception caused by the request
        Raises:
            InvalidRequestError - custom exception encapsulating grequests exception
        """
        raise InvalidRequestError('Request to {0} caused an exception: {1}'.format(request.url, exception))

    def _wait_for_response(self, requests):
        """Issues a batch of requests and waits for the responses.
        If some of the requests fail it will retry the failed ones up to `_max_retry` times.

        Args:
            requests - A list of requests
        Returns:
            A list of `requests.models.Response` objects
        Raises:
            InvalidRequestError - if any of the requests returns "403 Forbidden" response
        """
        responses_for_requests = OrderedDict.fromkeys(requests)

        for retry in range(self._max_retry):
            try:
                logging.debug('Try #{0}'.format(retry + 1))
                self._availability_limiter.map_with_retries(requests, responses_for_requests)

                failed_requests = []
                for request, response in responses_for_requests.items():
                    if not response:
                        failed_requests.append(request)

                if not failed_requests:
                    break

                logging.warning('Try #{0}. Expected {1} successful response(s) but only got {2}.'.format(
                    retry + 1, len(requests), len(requests) - len(failed_requests)))

                # retry only for the failed requests
                requests = failed_requests
            except InvalidRequestError:
                raise
            except Exception as e:
                # log the exception for the informative purposes and pass to the next iteration
                logging.exception('Try #{0}. Exception occured: {1}. Retrying.'.format(retry + 1, e))
                pass

        if failed_requests:
            logging.warning('Still {0} failed request(s) after {1} retries:'.format(len(failed_requests), self._max_retry))
            for failed_request in failed_requests:
                failed_response = failed_request.response
                if failed_response is not None:
                    # in case response text does contain some non-ascii characters
                    failed_response_text = failed_response.text.encode('ascii', 'xmlcharrefreplace')
                    logging.warning('Request to {0} failed with status code {1}. Response text: {2}'.format(
                        failed_request.url, failed_response.status_code, failed_response_text))
                else:
                    logging.warning('Request to {0} failed with None response.'.format(failed_request.url))

        return list(responses_for_requests.values())

    def _convert_to_json(self, response):
        """Converts response to JSON.
        If the response cannot be converted to JSON then `None` is returned.

        Args:
            response - An object of type `requests.models.Response`
        Returns:
            Response in JSON format if the response can be converted to JSON. `None` otherwise.
        """
        try:
            return response.json()
        except ValueError:
            logging.warning('Expected response in JSON format from {0} but the actual response text is: {1}'.format(
                response.request.url, response.text))
        return None

    def _multi_request(self, verb, urls, query_params, data, to_json=True, send_as_file=False):
        """Issues multiple batches of simultaneous HTTP requests and waits for responses.

        Args:
            verb - MultiRequest._VERB_POST or MultiRequest._VERB_GET
            urls - A string URL or list of string URLs
            query_params - None, a dict, or a list of dicts representing the query params
            data - None, a dict or string, or a list of dicts and strings representing the data body.
            to_json - A boolean, should the responses be returned as JSON blobs
        Returns:
            If multiple requests are made - a list of dicts if to_json, a list of grequest.response otherwise
            If a single request is made, the return is not a list
        Raises:
            InvalidRequestError - if no URL is supplied or if any of the requests returns 403 Access Forbidden response
        """
        if not urls:
            raise InvalidRequestError('No URL supplied')

        # Break the params into batches of request_params
        request_params = self._zip_request_params(urls, query_params, data)
        batch_of_params = [request_params[pos:pos + self._max_requests] for pos in range(0, len(request_params), self._max_requests)]

        # Iteratively issue each batch, applying the rate limiter if necessary
        all_responses = []
        for param_batch in batch_of_params:
            if self._rate_limiter:
                self._rate_limiter.make_calls(num_calls=len(param_batch))

            requests = []
            for url, query_param, datum in param_batch:
                requests.append(self._create_request(verb, url, query_params=query_param, data=datum, send_as_file=send_as_file))

            responses = self._wait_for_response(requests)
            for response in responses:
                if response:
                    all_responses.append(self._convert_to_json(response) if to_json else response)
                else:
                    all_responses.append(None)

        return all_responses

    def post_file(self, url, file, to_json=True):
        request = self._create_request(MultiRequest._VERB_POST, url)
        return request

    @classmethod
    def error_handling(cls, fn):
        """Decorator to handle errors while calling out to grequests."""
        def wrapper(*args, **kwargs):
            try:
                result = fn(*args, **kwargs)
                return result
            except InvalidRequestError as e:
                write_exception(e)

                if hasattr(e, 'request'):
                    write_error_message('request {0}'.format(repr(e.request)))
                if hasattr(e, 'response'):
                    write_error_message('response {0}'.format(repr(e.response)))

                raise e
        return wrapper
