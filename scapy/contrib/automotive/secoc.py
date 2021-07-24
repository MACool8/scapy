# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Martin Albert <macool8@t-online.de>
# This program is published under a GPLv2 license

# This is an implementation for Scapy to communicate with devices which have SecOc implemented
# SecOc is an AUTOSAR module described in the AUTOSAR document
# "Specification of Secure Onboard Communication" (Doc. Id: 654)

# scapy.contrib.description = Secure Onboard Communication (SecOc)
# scapy.contrib.status = loads

from scapy.packet import Packet
from scapy.config import conf
from scapy.error import log_loading
from enum import Enum


class FreshnessModes(Enum):
    Counter = 1
    Timestamp = 2

class FreshnessValueManager():
    def counter_increment(self):
        self.value += 1

    value: int = 0
    increment_function = counter_increment
    length: int = 0
    mode: FreshnessModes = FreshnessModes.Counter

    def FM_GetValueAndIncrease(self):
        return_value = self.value
        self.increment_function()
        return return_value

    def FM_GetValue(self):
        return self.value

    def FM_VerifyFreshness(self):


class Ciphers(Enum):
    AES256 = 1
    AES128 = 2
    RSA = 3

class CryptoServiceManager():
    def Csm_MacGenerate(self):
        Exception("Not Implemented yet")

    def Csm_MacVerify(self):
        Exception("Not Implemented yet")

    def Csm_SignatureGenerate(self):
        Exception("Not Implemented yet")

    def Csm_SignatureVerify(self):
        Exception("Not Implemented yet")

    def Csm_KeyElementSet(self):
        Exception("Not Implemented yet")

    def Csm_KeySetVelid(self):
        Exception("Not Implemented yet")


class SecOC(Packet):
    payload: bytes
    symmetric_key: bytes
    asymmetric_encrypt_key: bytes
    asymmetric_decrypt_key: bytes
    cipher: Ciphers = Ciphers.AES256
    freshness_length: int = 0
    truncate_freshness_length: int = 0
    truncate_authenticator_length: int = 0


#Errors:
# Freshness Value is still naive: Should be like on page 138 of AUTOSAR_SWS_SecureOnboardCommunication Specification
# Ciphers Enum should include a lot more ciphers as described in AUTOSAR_SWS_CryptoServiceManager
# Keys in SecOC Packet should be stored inside Crypto Service Manager
