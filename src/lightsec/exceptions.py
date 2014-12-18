"""
Created on 30/11/2014

@author: Aitor Gomez Goiri
"""


class UnauthorizedException(Exception):
    def __init__(self):
        super(Exception, self).__init__("The user is not authorized to get the data.")


class NoLongerAuthorizedException(UnauthorizedException):
    def __init__(self, message):
        super(Exception, self).__init__("The user is not longer authorized to get the data.")
