# -*- coding: utf-8 -*- 
'''
Created on 24/08/2014

Key derivation functions.

@author: Aitor Gomez Goiri
'''
from abc import ABCMeta, abstractmethod

class AbstractKeyDerivationFunction(object):
    """
    Class representing an abstract key derivation function.
    """
    # TODO Rename it. The current name sounds confusing in the OO logic
    # TODO Rename the methods not to sound too NIST800-108 specific (which is the only KDF example I know right now)
    #      Maybe checking https://docs.python.org/2/library/hashlib.html#key-derivation-function
    
    __metaclass__ = ABCMeta
    
    def __init__(self, outputSizeBits):
        self.outputSizeBits = outputSizeBits
    
    @abstractmethod
    def derive_key(self, fixedInput):
        pass


class KeyDerivationFunctionFactory(object):
    
    def __init__(self, kdf_class, digestmod, outputSizeBits):
        assert issubclass(kdf_class, AbstractKeyDerivationFunction), "The first parameter must be a AbstractKeyDerivationFunction"
        self.kdf_class = kdf_class
        self.digestmod = digestmod
        self.outputSizeBits = outputSizeBits
    
    def create_function(self, secret):
        return self.kdf_class(self.digestmod, secret, self.outputSizeBits)


class Nist800(AbstractKeyDerivationFunction):
    """
    Class representing the NIST 800-108 key derivation function in counter mode.
    """
    
    def __init__(self, digestmod, secret, outputSizeBits):
        super(Nist800, self).__init__(outputSizeBits)
        from kdf.lcrypto import NIST
        self.kdf = NIST()
        self.kdf.set_hmac(digestmod, secret)
    
    def derive_key(self, fixedInput):
        return str( self.kdf.derive_key(self.outputSizeBits, fixedInput) )