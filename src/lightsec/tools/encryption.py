"""
Created on 24/08/2014

@author: Aitor Gomez Goiri
"""
from abc import ABCMeta, abstractmethod


class AbstractCipher(object):
    """
    Class representing an abstract key derivation function.
    """
    # TODO Rename it. The current name sounds confusing in the OO logic
    # TODO Rename the methods not to sound too NIST800-108 specific (which is the only KDF example I know right now)
    # Maybe checking https://docs.python.org/2/library/hashlib.html#key-derivation-function

    __metaclass__ = ABCMeta

    @abstractmethod
    def encrypt(self, message, passphrase=None):
        assert passphrase is not None or self.passphrase is not None

    @abstractmethod
    def decrypt(self, encrypted, passphrase=None):
        assert passphrase is not None or self.passphrase is not None


class AESCTRCipher(AbstractCipher):
    """
    AES in counter mode.
    """

    def __init__(self, init_counter, default_passphrase=None):
        self.obj = self._create_cypher_object(default_passphrase, init_counter)

    def _create_cypher_object(self, passphrase, init_counter):
        if passphrase is None:
            return None

        from Crypto.Cipher import AES
        from Crypto.Util import Counter

        ctr = Counter.new(128, initial_value=init_counter)  # initial_value should change (default=1)
        # key_len = len(passphrase)
        # if key_len not in (16, 24, 32):
        #    if key_len>32:
        #        print "WARNING: the key can be 32 bits long at maximum, therefore it will be shortened to this length."
        #    else:
        #        print "ERROR: the key must be 16, 24 or 32 bits long"
        # it must be a read-only buffer or a string, not a bytearray!
        key = buffer(passphrase)
        return AES.new(key, AES.MODE_CTR, counter=ctr)

    def encrypt(self, message, passphrase=None):
        assert passphrase is not None or self.obj is not None
        lobj = self.obj if passphrase is None else self._create_cypher_object(passphrase)
        return lobj.encrypt(message)

    def decrypt(self, ciphertext, passphrase=None):
        assert passphrase is not None or self.obj is not None
        lobj = self.obj if passphrase is None else self._create_cypher_object(passphrase)
        return lobj.decrypt(ciphertext)