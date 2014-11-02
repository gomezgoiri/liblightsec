'''
Created on 02/11/2014

@author: Aitor Gomez Goiri
'''
from abc import ABCMeta, abstractmethod

class AbstractSecretStore(object):
    
    __metaclass__ = ABCMeta
    
    @abstractmethod
    def install_auth_secret(self, identifier, secret):
        pass
    
    @abstractmethod
    def install_enc_secret(self, identifier, secret):
        pass
    
    @abstractmethod
    def get_auth_secret(self, identifier):
        pass
    
    @abstractmethod
    def get_enc_secret(self, identifier):
        pass


class MemorySecretStore(AbstractSecretStore):
    
    def __init__(self):
        super(MemorySecretStore, self).__init__()
        self._auth_secrets = {}
        self._enc_secrets = {}
    
    def install_auth_secret(self, identifier, secret):
        self._auth_secrets[identifier] = secret
    
    def install_enc_secret(self, identifier, secret):
        self._enc_secrets[identifier] = secret
    
    def get_auth_secret(self, identifier):
        return self._auth_secrets[identifier]
    
    def get_enc_secret(self, identifier):
        return self._enc_secrets[identifier]