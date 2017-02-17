# -*- coding: utf-8 -*-
#
from six.moves import builtins
import simplejson
import testify as T
from mock import mock_open
from mock import patch

from threat_intel.util.api_cache import ApiCache


def assert_cache_written(mock_write, patched_open):
    T.assert_equal(mock_write.call_count, 1)

    for call in patched_open.mock_calls:
        name, args, kwargs = call
        if '().write' != name:
            continue

        return simplejson.loads(args[0])
    return None


def assert_cache_not_written(mock_write):
    T.assert_falsey(mock_write.called)
    return None


class ApiCacheFileIOTest(T.TestCase):

    """Allows for setting and retrieving results of API calls."""

    @T.setup
    def setup_filename(self):
        self._file_name = '/tmp/any_name_will_do'

    def _open_cache(self, initial_contents=None, update_cache=True):
        """Creates an ApiCache object, mocking the contents of the cache on disk.

        Args:
                initial_contents: A dict containing the initial contents of the cache
                update_cache: Specifies whether ApiCache should write out the
                              cache file when closing it
        Returns:
                ApiCache
        """
        if not initial_contents:
            initial_contents = {}

        file_contents = simplejson.dumps(initial_contents)
        mock_read = mock_open(read_data=file_contents)
        with patch.object(builtins, 'open', mock_read, create=True):
            api_cache = ApiCache(self._file_name, update_cache=update_cache)
            return api_cache

    def _close_cache(self, api_cache, cache_written=True):
        """Closes an ApiCache and reads the final contents that were written to disk.

        Args:
                api_cache: An ApiCache instance
                cache_written: Specifies whether it should test that the cache
                               was written out to the cache file or whether to
                               test that it was not written out
        Returns:
                A dict representing the contents of the cache that was written
                out to the cache file or `None` in case cache was not expected
                to be written out
        """
        mock_write = mock_open()
        with patch.object(builtins, 'open', mock_write, create=True) as patched_open:
            api_cache.close()

            if cache_written:
                return assert_cache_written(mock_write, patched_open)

            return assert_cache_not_written(mock_write)

    def test_create_cache(self):
        initial_contents = {
            'banana': {
                'apple': ['pear', 'panda'],
                'sumo': False,
                'rebel_base_count': 42
            },
            'skiddo': 'Fo Sure',
            'pi': 3.1415
        }

        api_cache = self._open_cache(initial_contents)
        final_contents = self._close_cache(api_cache)
        T.assert_equal(initial_contents, final_contents)

    def test_persist_objects(self):
        contents_to_load = {
            'api1': {
                'key1': 'value1',
                'key2': 11,
                        'key3': {'some': 'dict'},
                        'key4': ['a', 'list']
            },
            'api2': {
                'key1': 'value42',
                'key4': 'lavash bread'
            }
        }

        # Open an empty cache
        api_cache = self._open_cache()

        # Load the cache
        for api_name in contents_to_load.keys():
            for key in contents_to_load[api_name]:
                api_cache.cache_value(api_name, key, contents_to_load[api_name][key])

        # Verify the cache
        for api_name in contents_to_load.keys():
            for key in contents_to_load[api_name]:
                expected_val = contents_to_load[api_name][key]
                actual_val = api_cache.lookup_value(api_name, key)
                T.assert_equal(expected_val, actual_val)

        # Close the cache
        final_contents = self._close_cache(api_cache)
        T.assert_equal(contents_to_load, final_contents)

    def test_do_not_update_cache(self):
        initial_contents = {
            'api1': {
                'bingo': 'woohoo'
            },
            'api2': {
                'bongo': 'boo'
            }
        }
        api_cache = self._open_cache(initial_contents, False)
        final_contents = self._close_cache(api_cache, cache_written=False)
        T.assert_equal(None, final_contents)
