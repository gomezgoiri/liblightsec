'''
Created on 26/08/2014

@author: Aitor Gomez Goiri
'''

from time import time
from random import random, randint
from lightsec.store.secrets import AbstractSecretStore, MemorySecretStore

class BaseStationHelper(object):
    
    def __init__(self, kdf_factory, store=None):
        self._kdf_factory = kdf_factory
        if store is None:
            self._store = MemorySecretStore()
        else:
            assert isinstance(store, AbstractSecretStore)
    
    def install_secrets(self, id_sensor, secret_auth, secret_enc):
        self._store.install_auth_secret(id_sensor, secret_auth)
        self._store.install_enc_secret(id_sensor, secret_enc)
    
    def create_keys(self, id_user, id_sensor, validity_seconds):
        # TODO id_user should be authenticated first using the credentials sent
        # And then and only then...
        stuff = {}
        # TODO use better crypto-suite's random salt generator 
        stuff["a"] = str( random() ) # TODO check how to  KDF (MSS, {a, IDA || init time || exp time_})
        stuff["init_time"] = time()
        stuff["exp_time"] = stuff["init_time"] + validity_seconds * 1000
        
        kdf_enc = self._kdf_factory.create_function( self._store.get_enc_secret(id_sensor), stuff["a"] )
        stuff["kenc"] = kdf_enc.derive_key( "%s%d%d" % (id_user, stuff["init_time"], stuff["exp_time"]) ) # TODO use id_user here
        kdf_auth = self._kdf_factory.create_function( self._store.get_auth_secret(id_sensor), stuff["a"] )
        stuff["kauth"] = kdf_auth.derive_key( "%s%d%d" % (id_user, stuff["init_time"], stuff["exp_time"]) ) # TODO use id_user here
        return stuff


class SensorHelper(object):
    
    def __init__(self, kdf_factory, hmac_class, cipher_class, secret_store=None):
        if secret_store is None:
            self._store = MemorySecretStore()
        else:
            assert isinstance(secret_store, AbstractSecretStore)
        
        self._kdf_factory = kdf_factory
        self._hmac_class = hmac_class
        self._cipher_class = cipher_class
        self._cached_keys = {}
    
    # It might install one or many (e.g. for group access)
    def install_secrets(self, secret_auth, secret_enc, identifier="default"):
        self._store.install_auth_secret(identifier, secret_auth)
        self._store.install_enc_secret(identifier, secret_enc)
    
    def _check_expiration_time(self, exp_time):
        if exp_time < time():
            raise Exception("The user is not longer authorized to get the data.")
    
    def create_keys(self, id_user, a, init_time, exp_time, ctr, identifier="default"):
        self._check_expiration_time( exp_time )
        
        # KDF (MSSenc, {a, IDA || init time || exp time_})
        kdf_enc = self._kdf_factory.create_function( self._store.get_enc_secret(identifier), a )
        kenc = kdf_enc.derive_key( "%s%d%d" % (id_user, init_time, exp_time) )
        # KDF (MSSauth, {a, IDA || init time || exp time_})
        kdf_auth = self._kdf_factory.create_function( self._store.get_auth_secret(identifier), a )
        kauth = kdf_auth.derive_key( "%s%d%d" % (id_user, init_time, exp_time) )
        
        # TODO if self.cache_keys:
        self._cached_keys[id_user] = {}
        self._cached_keys[id_user]["kenc"] = kenc
        self._cached_keys[id_user]["kauth"] = kauth
        self._cached_keys[id_user]["exp_time"] = exp_time
        self._cached_keys[id_user]["cipher"] = self._cipher_class( ctr, kenc )
        
        return kenc, kauth
    
    def check_is_authorized(self, id_user):
        if id_user not in self._cached_keys:
            raise Exception("The user is not authorized to get the data.")
        self._check_expiration_time( self._cached_keys[id_user]["exp_time"] )
    
    def encrypt(self, id_user, message):
        self.check_is_authorized( id_user )
        return self._cached_keys[id_user]["cipher"].encrypt( message )
    
    def decrypt(self, id_user, enc_message):
        self.check_is_authorized( id_user )
        return self._cached_keys[id_user]["cipher"].decrypt( enc_message )
    
    def _first_communication_mac(self, key, message, user_id, a, init_time, exp_time, ctr):
        hmac = self._hmac_class( key )
        hmac.update( message )
        hmac.update( user_id )
        hmac.update( a )
        hmac.update( str(init_time) )
        hmac.update( str(exp_time) )
        hmac.update( str(ctr) )
        return hmac.digest()
    
    def _normal_communication_mac(self, key, message):
        hmac = self._hmac_class( key )
        hmac.update( message )
        return hmac.digest()
    
    def mac(self, message, id_user):
        self.__assert_previous_create_keys_call( id_user )
        key = self._cached_keys[id_user]["kauth"]
        return self._normal_communication_mac( key, message )
    
    def __assert_previous_create_keys_call(self, id_user):
        # the must have been called before!!!
        # the temporal coupling I was trying to avoid doest not work!
        assert id_user is not None and \
                id_user in self._cached_keys and \
                "kauth" in self._cached_keys[id_user] and \
                "exp_time" in self._cached_keys[id_user], \
                "Note that create_keys must be called first."
        
    
    def msg_is_authentic(self, message, mac_to_verify, id_user, a=None, init_time=None, ctr=None):
        self.__assert_previous_create_keys_call( id_user )
        key = self._cached_keys[id_user]["kauth"]
        exp_time = self._cached_keys[id_user]["exp_time"]
        
        if not a and not init_time and not ctr:
            mac = self._normal_communication_mac( key, message )
        else:
            assert a is not None
            assert init_time is not None
            assert ctr is not None
            mac = self._first_communication_mac( key, message, id_user, a, init_time, exp_time, ctr )
        return mac_to_verify == mac


class UserHelper(object): # One instance per communication (with a sensor or a group of sensors)
    
    # We could check the validity of a key before getting an error from the sensor too.
    # TODO Decide which option is better. 
    
    def __init__(self, sensor_id, kenc, cipher_class, kauth, hmac_class, id_user, a, init_time, exp_time):
        self._sensor_id = sensor_id # TODO, it's maybe not needed here
        # stored as an argument because it must be sent to the sensor afterwards
        ctr = randint(0,500)
        self._cipher = cipher_class(ctr, kenc)
        self._hmac_class = hmac_class
        # data only used for the first communication mac:
        self._kauth = kauth
        self._id_user = id_user
        self._a = a
        self._init_time = init_time
        self._exp_time = exp_time
        self.initial_counter = ctr # shared afterwards
        # to discriminate the first communication and the rest
        self._first_mac = False
    
    def encrypt(self, message):
        return self._cipher.encrypt( message )
    
    def decrypt(self, enc_message):
        return self._cipher.decrypt( enc_message )
    
    def mac(self, message):
        hmac = self._hmac_class( self._kauth )
        hmac.update( message )
        if not self._first_mac:
            hmac.update( self._id_user )
            hmac.update( self._a )
            hmac.update( str(self._init_time) )
            hmac.update( str(self._exp_time) )
            hmac.update( str(self.initial_counter) )
            self._first_mac = True
        return hmac.digest()
    
    def msg_is_authentic(self, message, mac_to_verify):
        mac = self.mac( message )
        return mac_to_verify==mac