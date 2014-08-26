'''
Created on 24/08/2014

@author: Aitor Gomez Goiri
'''
from abc import ABCMeta, abstractmethod


class AbstractCipher(object):
    """
    Class representing an abstract key derivation function.
    """
    # TODO Rename it. The current name sounds confusing in the OO logic
    # TODO Rename the methods not to sound too NIST800-108 specific (which is the only KDF example I know right now)
    #      Maybe checking https://docs.python.org/2/library/hashlib.html#key-derivation-function
    
    __metaclass__ = ABCMeta
    
    @abstractmethod
    def encrypt(self, message, passphrase = None):
        assert passphrase!=None or self.passphrase!=None
    
    @abstractmethod
    def decrypt(self, encrypted, passphrase = None):
        assert passphrase!=None or self.passphrase!=None


class AESCTRCipher(AbstractCipher):
    """
    AES in counter mode.
    """
    
    def __init__(self, default_passphrase = None):
        self.obj = self._create_cypher_object(default_passphrase)
    
    def _create_cypher_object(self, passphrase, init_counter):
        if passphrase is None:
            return None
        
        from Crypto.Cipher import AES
        from Crypto.Util import Counter
        ctr = Counter.new(128) # initial_value should change (default=1)
        return AES.new(passphrase, AES.MODE_CTR, counter=ctr)
    
    def encrypt(self, message, passphrase = None):
        assert passphrase!=None or self.obj!=None
        lobj = self.obj if passphrase is None else self._create_cypher_object(passphrase)
        return lobj.encrypt(message)
    
    def decrypt(self, ciphertext, passphrase = None):
        assert passphrase!=None or self.obj!=None
        lobj = self.obj if passphrase is None else self._create_cypher_object(passphrase)
        return lobj.decrypt(ciphertext)