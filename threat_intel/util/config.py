import os
import yaml
from threat_intel.exceptions import MissingConfigError


def config_get_deep(key, default=None):
    """Reads from the config.

    Args:
        key: Dictionary key to lookup in config
        default: Value to return if key is not found
    Returns:
        Value from config or default if not found otherwise
    """
    return DictUtils.get_deep(_read_config(), key, default)

def _read_config():
    """Reads and parses the YAML file.

    Returns:
        dict of config
    """
    with open(_config_file_path()) as source:
        return yaml.load(source.read())


def _config_file_path():
    """Find the path to the config file.

    Returns:
        String file path
    Raises:
        MissingConfigError if no config file is found
    """
    for loc in os.curdir, os.path.expanduser('~'), os.environ.get('OSXCOLLECTOR_CONF', ''):
        path = os.path.join(loc, 'osxcollector.yaml')
        if os.path.exists(path):
            return path
    raise MissingConfigError()


class DictUtils(object):

    """A set of method for manipulating dictionaries."""

    @classmethod
    def _link_path_to_chain(cls, path):
        """Helper method for get_deep
        Args:
            path: A str representing a chain of keys separated '.' or an enumerable set of strings
        Returns:
            an enumerable set of strings
        """
        if path == '':
            return []
        elif type(path) in (list, tuple, set):
            return path
        else:
            return path.split('.')

    @classmethod
    def _get_deep_by_chain(cls, x, chain, default=None):
        """Grab data from a dict using a ['key1', 'key2', 'key3'] chain param to do deep traversal.
        Args:
            x: A dict
            chain: an enumerable set of strings
            default: A value to return if the path can not be found
        Returns:
            The value of the key or default
        """
        if chain == []:
            return default
        try:
            for link in chain:
                try:
                    x = x[link]
                except (KeyError, TypeError):
                    x = x[int(link)]
        except (KeyError, TypeError, ValueError):
            x = default
        return x

    @classmethod
    def get_deep(cls, x, path='', default=None):
        """Grab data from a dict using a 'key1.key2.key3' path param to do deep traversal.
        Args:
            x: A dict
            path: A 'deep path' to retrieve in the dict
            default: A value to return if the path can not be found
        Returns:
            The value of the key or default
        """
        chain = cls._link_path_to_chain(path)
        return cls._get_deep_by_chain(x, chain, default=default)
