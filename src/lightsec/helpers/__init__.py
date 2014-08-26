'''
Created on 26/08/2014

@author: Aitor Gomez Goiri
'''

from time import time
from random import random

class BaseStationHelper(object):
    
    def __init__(self, kdf_factory):
        self.kdf_factory = kdf_factory
        self._auth_secrets = {}
        self._enc_secrets = {}
    
    def install_secret(self, id_user, secret_auth, secret_enc):
        self._auth_secrets[id_user] = secret_auth
        self._enc_secrets[id_user] = secret_enc
    
    def create_keys(self, id_user, validity_seconds):
        stuff = {}
        stuff["a"] = random()
        stuff["init_time"] = time()
        stuff["exp_time"] = stuff["init_time"] + validity_seconds * 1000
        
        kdf = self.kdf_factory.create_function( stuff["a"] )
        stuff["kenc"] = kdf.derive_key( self._enc_secrets[id_user] )
        stuff["kauth"] = kdf.derive_key( self._auth_secrets[id_user] )
        
        return stuff


class SensorHelper(object):
    
    def __init__(self, kdf_factory, cipher_class, secret_auth, secret_enc):
        self.kdf_factory = kdf_factory
        self.cipher_class = cipher_class
        self._secret_auth = secret_auth
        self._secret_enc = secret_enc
        self._cached_keys = {}
    
    def _check_expiration_time(self, exp_time):
        if exp_time < time():
            raise Exception("The user is not longer authorized to get the data.")
    
    def create_keys(self, id_user, a, init_time, exp_time, ctr):
        self._check_expiration_time( exp_time )
        
        kdf = self.kdf_factory.create_function( a )
        kenc = kdf.derive_key( self._secret_enc )
        kauth = kdf.derive_key( self._secret_auth )
        
        if self.cache_keys:
            self._cached_keys[id_user] = {}
            self._cached_keys[id_user]["kenc"] = kenc
            self._cached_keys[id_user]["kauth"] = kauth
            self._cached_keys[id_user]["exp_time"] = exp_time
            self._cached_keys[id_user]["cipher"] = self.cipher_class( kenc, ctr )
        
        return kenc, kauth
    
    def check_is_authorized(self, id_user):
        if id_user not in self._cached_keys:
            raise Exception("The user is not authorized to get the data.")
        self._check_expiration_time( self._cached_keys[id_user]["exp_time"] )
    
    def encrypt(self, id_user, message):
        self.check_is_authorized( id_user )
        return self._cached_keys["cipher"].encrypt( message )
    
    def decrypt(self, id_user, enc_message):
        self.check_is_authorized( id_user )
        return self._cached_keys["cipher"].decrypt( enc_message )