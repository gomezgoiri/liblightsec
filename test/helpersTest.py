'''
Created on 26/08/2014

@author: Aitor Gomez Goiri
'''

import unittest
import hashlib
from lightsec.helpers import BaseStationHelper, SensorHelper
from lightsec.tools.kdf import KeyDerivationFunctionFactory, Nist800
from lightsec.tools.encryption import AESCTRCipher


class HelpersTest(unittest.TestCase):
    
    def setUp(self):
        self.kdf_factory = KeyDerivationFunctionFactory( Nist800, hashlib.sha256, 512 ) 
        self.base_station = BaseStationHelper( self.kdf_factory )
        self.base_station.install_secret("user1", "authms1", "encms1")
    
    def test_encryption(self):
        stuff = self.base_station.create_keys( "user1", 10 )
        self.sensor = SensorHelper( KeyDerivationFunctionFactory(),
                                    AESCTRCipher, stuff["kenc"], stuff["kauth"] )
        
        kenc, kauth = self.sensor.create_keys( "user1", stuff["a"], stuff["init_time"], stuff["exp_time"], stuff["ctr"] )
        self.assertSequenceEqual( kenc, stuff["kenc"] )
        self.assertSequenceEqual( kauth, stuff["kauth"] )


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()