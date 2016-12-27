import os
import time
import logging
import xxhash


# Metaclass to provide Singleton to RestCache
# http://stackoverflow.com/questions/6760685/creating-a-singleton-in-python/6798042#6798042
class SingletonRestCache(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(SingletonRestCache, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class RestCache(object):
    __metaclass__ = SingletonRestCache
    # Folder where to store cached entries
    CACHED_ROOT_FOLDER = "~/.libParser/cache/"
    # How old, in seconds, cached files are to be used?
    DEFAULT_EXPIRE_AFTER = 86400

    def __init__(self, timeout=DEFAULT_EXPIRE_AFTER):
        self.cached_main_folder = os.path.expanduser(self.CACHED_ROOT_FOLDER)
        self.setup_cache_folders()
        self.oldest_mtime = round(time.time() - timeout)

    @staticmethod
    def __make_hash(value, prefix=''):
        """Creates hash based on input"""
        _hash = str(xxhash.xxh64(value).hexdigest())
        if prefix != '':
            prefix += '_'
        return prefix + _hash

    def get_or(self, url, prefix='', default=''):
        """Returns cached element designated by URL hash, or contents of 'default' parameter"""
        _reply = default
        _f = None
        filename = self.cached_main_folder + self.__make_hash(url, prefix)

        try:
            if os.path.exists(filename):
                if os.path.getmtime(filename) <= self.oldest_mtime:
                    # cached data is too old: remove and return default response
                    os.remove(filename)
                else:
                    logging.debug('RestCase.get_or: Reading file {} for url {}'.format(filename, url))
                    _f = open(filename, "r")
                    ll = _f.readlines()
                    _reply = "".join(ll)
        except IOError as (_, strerror):
            logging.error('RestCache.get_or: Error reading file {} for {}: {}'.format(filename, url, strerror))
            _reply = default
        finally:
            if _f is not None:
                        _f.close()

        return _reply

    def update(self, url, value, prefix=''):
        """Updates/creates cache file designated by URL hash with the contents of 'value'"""
        _success = True
        filename = self.cached_main_folder + self.__make_hash(url, prefix)
        if os.path.exists(filename):
            os.remove(filename)
        _f = None
        try:
            _f = open(filename, "w")
            _f.write(value)
        except IOError as (_, strerror):
            logging.error('RestCache.update: Error updating file {} for {}: {}'.format(filename, url, strerror))
            _success = False
        finally:
            if _f is not None:
                _f.close()

        return _success

    def setup_cache_folders(self):
        """Check if folders exist and create otherwise"""
        def create_if_not_there(path):
            if os.path.exists(path):
                if os.path.isdir(path):
                    return
                else:
                    logging.error("File exists and it's not a folder!")
            else:
                os.makedirs(path, mode=0o755)

        create_if_not_there(self.cached_main_folder)

