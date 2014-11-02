'''
Created on 02/11/2014

@author: Aitor Gomez Goiri
'''

from time import time
from abc import ABCMeta, abstractmethod

class UnauthorizedException(Exception):
    def __init__(self):
        super(Exception, self).__init__("The user is not authorized to get the data.")

class NoLongerAuthorizedException(UnauthorizedException):
    def __init__(self, message):
        super(Exception, self).__init__("The user is not longer authorized to get the data.")

class AbstractKeyCache(object):
    
    __metaclass__ = ABCMeta
    
    @abstractmethod
    def cache(self, identifier, key_auth, key_enc, expiration_time, cipher_obj):
        pass
    
    @abstractmethod
    def clear(self, identifier):
        pass
                                   
    def _check_expiration_time(self, identifier):
        if self.get_exp_time(identifier) < time():
            self.clear(identifier)
            raise NoLongerAuthorizedException()
    
    def _check_is_authorized(self, identifier):
        if not self._is_cached(identifier):
            raise UnauthorizedException()
        self._check_expiration_time(identifier)
    
    @abstractmethod
    def _is_cached(self, identifier):
        pass
    
    @abstractmethod
    def get_exp_time(self, identifier):
        pass
    
    @abstractmethod
    def get_auth_key(self, identifier):
        pass
    
    @abstractmethod
    def get_enc_key(self, identifier):
        pass
    
    @abstractmethod
    def get_cipher(self, identifier):
        pass


class MemoryKeyCache(AbstractKeyCache):
    
    def __init__(self):
        super(MemoryKeyCache, self).__init__()
        self._cached_keys = {}
    
    def cache(self, identifier, key_auth, key_enc, expiration_time, cipher_obj):
        self._cached_keys[identifier] = {}
        self._cached_keys[identifier]["kauth"] = key_auth
        self._cached_keys[identifier]["kenc"] = key_enc
        self._cached_keys[identifier]["exp_time"] = expiration_time
        self._cached_keys[identifier]["cipher"] = cipher_obj
    
    def clear(self, identifier):
        del self._cached_keys[identifier]
    
    def _is_cached(self, identifier):
        return identifier in self._cached_keys
    
    def get_exp_time(self, identifier):
        return self._cached_keys[identifier]["exp_time"]
    
    def get_auth_key(self, identifier):
        return self._cached_keys[identifier]["kauth"]
    
    def get_enc_key(self, identifier):
        return self._cached_keys[identifier]["kenc"]
    
    def get_cipher(self, identifier):
        self._check_is_authorized(identifier)
        return self._cached_keys[identifier]["cipher"]