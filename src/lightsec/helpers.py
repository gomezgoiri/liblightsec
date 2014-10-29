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
    
    def install_secret(self, id_sensor, secret_auth, secret_enc):
        self._auth_secrets[id_sensor] = secret_auth
        self._enc_secrets[id_sensor] = secret_enc
    
    def create_keys(self, id_user, id_sensor, validity_seconds):
        # TODO id_user should be authenticated first using the credentials sent
        # And then and only then...
        stuff = {}
        # TODO use better crypto-suite's random salt generator 
        stuff["a"] = str( random() ) # TODO check how to  KDF (MSS, {a, IDA || init time || exp time_})
        stuff["init_time"] = time()
        stuff["exp_time"] = stuff["init_time"] + validity_seconds * 1000
        
        kdf_enc = self.kdf_factory.create_function( self._enc_secrets[id_sensor], stuff["a"] )
        stuff["kenc"] = kdf_enc.derive_key( "%s%d%d" % (id_user, stuff["init_time"], stuff["exp_time"]) ) # TODO use id_user here
        kdf_auth = self.kdf_factory.create_function( self._auth_secrets[id_sensor], stuff["a"] )
        stuff["kauth"] = kdf_auth.derive_key( "%s%d%d" % (id_user, stuff["init_time"], stuff["exp_time"]) ) # TODO use id_user here
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
        
        # KDF (MSSenc, {a, IDA || init time || exp time_})
        kdf_enc = self.kdf_factory.create_function( self._secret_enc, a )
        kenc = kdf_enc.derive_key( "%s%d%d" % (id_user, init_time, exp_time) )
        # KDF (MSSauth, {a, IDA || init time || exp time_})
        kdf_auth = self.kdf_factory.create_function( self._secret_auth, a )
        kauth = kdf_auth.derive_key( "%s%d%d" % (id_user, init_time, exp_time) )
        
        # TODO if self.cache_keys:
        self._cached_keys[id_user] = {}
        self._cached_keys[id_user]["kenc"] = kenc
        self._cached_keys[id_user]["kauth"] = kauth
        self._cached_keys[id_user]["exp_time"] = exp_time
        self._cached_keys[id_user]["cipher"] = self.cipher_class( ctr, kenc )
        
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