# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Martin Albert <macool8@t-online.de>
# This program is published under a GPLv2 license

# This is an implementation for Scapy to communicate with devices which have
# Secure Onboard Communication (SecOC) implemented.
# SecOC is an AUTOSAR module described in the AUTOSAR document
# "Specification of Secure Onboard Communication" (Doc. Id: 654)

# scapy.contrib.description = Secure Onboard Communication (SecOc)
# scapy.contrib.status = loads
import time

from scapy.packet import Packet
from scapy.config import conf
from scapy.error import log_loading
from enum import Enum
from Crypto.Cipher import AES
from Crypto.Hash import CMAC, HMAC, SHA1, SHA224, SHA256, SHA384, SHA512, SHA3_224, SHA3_256, SHA3_384, SHA3_512, BLAKE2s, SHAKE128, SHAKE256


class FreshnessModes(Enum):
    Counter = 1
    Timestamp = 2

class FreshnessValueManager():
    def _counter_increment(self):
        self.value += 1

    value: int = 0
    FM_Length: int = 0 # actual internal length used for the freshness value
    FM_TruncatedLength: int = 0 # Length of Freshness represented in the Packet (bits)
    increment_function = _counter_increment
    FM_Mode: FreshnessModes = FreshnessModes.Counter
    timestampoffset: int = 0

    def __int__(self, Mode: FreshnessModes = FreshnessModes.Counter, InitialValua: int = None, TimeStampOffset: int = None):
        if InitialValua != None and type(InitialValua) == int:
            self.value = InitialValua

        if TimeStampOffset != None and type(TimeStampOffset) == int:
            self.timestampoffset = InitialValua

        self.FM_Mode = Mode

    def FM_GetValueAndIncrease(self):
        if self.mode == FreshnessModes.Counter:
            return_value = self.value
            self.increment_function()
            return return_value
        else:
            return int(time.time()) + self.timestampoffset

    def FM_GetValue(self):
        if self.mode == FreshnessModes.Counter:
            return self.value
        else:
            return int(time.time()) + self.timestampoffset

    def FM_VerifyFreshness(self, packet):
        return None


# Enumerated by SWS_Csm_01047
class Crypto_Algo(Enum):
    NOT_SET                 = 0x00  # Algorithm family is not set
    SHA1                    = 0x01  # SHA1 hash
    SHA2_224                = 0x02  # SHA2-224 hash
    SHA2_256                = 0x03  # SHA2-256 hash
    SHA2_384                = 0x04  # SHA2-384 hash
    SHA2_512                = 0x05  # SHA2-512 hash
    SHA2_512_224            = 0x06  # SHA2-512/224 hash
    SHA2_512_256            = 0x07  # SHA2-512/256 hash
    SHA3_224                = 0x08  # SHA3-224 hash
    SHA3_256                = 0x09  # SHA3-256 hash
    SHA3_384                = 0x0a  # SHA3-384 hash
    SHA3_512                = 0x0b  # SHA3-512 hash
    SHAKE128                = 0x0c  # SHAKE128 hash
    SHAKE256                = 0x0d  # SHAKE256 hash
    RIPEMD160               = 0x0e  # RIPEMD hash
    BLAKE_1_256             = 0x0f  # BLAKE-1-256 hash
    BLAKE_1_512             = 0x10  # BLAKE-1-512 hash
    BLAKE_2s_256            = 0x11  # BLAKE-2s-256 hash
    BLAKE_2s_512            = 0x12  # BLAKE-2s-512 hash
    _3DES                   = 0x13  # 3DES cipher
    AES                     = 0x14  # AES cipher
    CHACHA                  = 0x15  # ChaCha cipher
    RSA                     = 0x16  # RSA cipher
    ED25519                 = 0x17  # ED22518 elliptic curve
    BRAINPOOL               = 0x18  # Brainpool elliptic curve
    ECCNIST                 = 0x19  # NIST ECC elliptic curves
    RNG                     = 0x1b  # Random Number Generator
    SIPHASH                 = 0x1c  # SipHash
    ECCANSI                 = 0x1e  # Elliptic curve according to ANSI X9.62
    ECCSEC                  = 0x1f  # Elliptic curve according to SECG
    DRBG                    = 0x20  # Random number generator according to NIST
    FIPS186                 = 0x21  # Random number generator according to FIPS 186.
    PADDING_PKCS7           = 0x22  # Cipher padding according to PKCS.7
    PADDING_ONEWITHZEROS    = 0x23  # Cipher padding mode. Fill/ but first bit after the data is 1. Eg. "DATA" &
    PBKDF2                  = 0x24  # Password-Based Key Derivation Function 2
    KDFX963                 = 0x25  # ANSI X9.63 Public Key Cryptography
    DH                      = 0x26  # Diffie-Hellman
    CUSTOM                  = 0xff  # Custom algorithm family

# Enumerated by SWS_Csm_01048
class Crypto_Mode(Enum):
    NOT_SET             = 0x00  # Algorithm key is not set
    ECB                 = 0x01  # Blockmode: Electronic Code Book
    CBC                 = 0x02  # Blockmode: Cipher Block Chaining
    CFB                 = 0x03  # Blockmode: Cipher Feedback Mode
    OFB                 = 0x04  # Blockmode: Output Feedback Mode
    CTR                 = 0x05  # Blockmode: Counter Modex
    GCM                 = 0x06  # Blockmode: Galois/Counter Mode
    XTS                 = 0x07  # XOR-encryption-based tweakedcodebook mode with ciphertext stealing
    RSAES_OAEP          = 0x08  # RSA Optimal Asymmetric Encryption Padding
    RSAES_PKCS1_v1_5    = 0x09  # RSA encryption/ PKCS#1 v1.5 padding decryption with
    RSASSA_PSS          = 0x0a  # RSA Probabilistic Signature Scheme
    RSASSA_PKCS1_v1_5   = 0x0b  # RSA signature with PKCS#1 v1.5
    _8ROUNDS            = 0x0c  # 8 rounds (e.g. ChaCha8)
    _12ROUNDS           = 0x0d  # 12 rounds (e.g. ChaCha12)
    _20ROUNDS           = 0x0e  # 20 rounds (e.g. ChaCha20)
    HMAC                = 0x0f  # Hashed-based MAC
    CMAC                = 0x10  # Cipher-based MAC
    GMAC                = 0x11  # Galois MAC
    CTRDRBG             = 0x12  # Counter-based Deterministic Random
    SIPHASH_2_4         = 0x13  # Siphash-2-4
    SIPHASH_4_8         = 0x14  # Siphash-4-8
    PXXXR1              = 0x15  # ANSI R1 Curve
    CUSTOM              = 0xff  # Custom algorithm mode

class VerificationResultType(Enum):
    SECOC_VERIFICATIONSUCCESS   = 0x00
    SECOC_VERIFICATIONFAILURE   = 0x01
    SECOC_FRESHNESSFAILURE      = 0x02
    SECOCE_RE_FRESHNESS_FAILURE = 0x03

class CryptoServiceManager():
    CsmMacGenerateAlgorithmKeyLength: int = 0 # Size of the MAC key in bytes
    CsmMacGenerateResultLength: int = 0 # Size of the output MAC length in bytes
    CsmAlgo: Crypto_Algo = Crypto_Algo.AES
    CsmAlgoMode: Crypto_Mode = Crypto_Mode.CMAC
    CsmSecondaryAlgo: Crypto_Algo = Crypto_Algo.NOT_SET

    _symmetric_key: bytes = None
    _asymmetric_encrypt_key: bytes = None
    _asymmetric_decrypt_key: bytes = None

    def Csm_MacGenerate(self, Data_ID: bytes, I_PDU:bytes, FreshnessValue: bytes):
#        Allowed_CsmAlgo = [Crypto_Algo._3DES, Crypto_Algo.AES, Crypto_Algo.BLAKE_1_256, Crypto_Algo.BLAKE_1_512,
#                           Crypto_Algo.BLAKE_2s_256, Crypto_Algo.BLAKE_2s_512, Crypto_Algo.CHACHA, Crypto_Algo.CUSTOM,
#                           Crypto_Algo.RIPEMD160, Crypto_Algo.RNG, Crypto_Algo.SHA1, Crypto_Algo.SHA1,
#                           Crypto_Algo.SHA2_224, Crypto_Algo.SHA2_256, Crypto_Algo.SHA2_384, Crypto_Algo.SHA2_512,
#                           Crypto_Algo.SHA2_512_224, Crypto_Algo.SHA2_512_256, Crypto_Algo.SHA3_224,
#                           Crypto_Algo.SHA3_256, Crypto_Algo.SHA3_384, Crypto_Algo.SHA3_512]
#
#        Allowed_CsmAlgoModes = [Crypto_Mode.CMAC, Crypto_Mode.CTRDRBG, Crypto_Mode.CUSTOM, Crypto_Mode.GMAC,
#                                Crypto_Mode.HMAC, Crypto_Mode.NOT_SET, Crypto_Mode.SIPHASH_2_4, Crypto_Mode.SIPHASH_4_8]

        Cipher = None
        Authenticator_Raw = b"".join([Data_ID, I_PDU, FreshnessValue])
        if self.CsmAlgo ==  Crypto_Algo.AES:
            Cipher = AES
        elif self.CsmAlgo ==  Crypto_Algo.SHA1:
            Cipher = SHA1
        elif self.CsmAlgo ==  Crypto_Algo.SHA2_224:
            Cipher = SHA224
        elif self.CsmAlgo ==  Crypto_Algo.SHA2_256:
            Cipher = SHA256
        elif self.CsmAlgo ==  Crypto_Algo.SHA2_384:
            Cipher = SHA384
        elif self.CsmAlgo ==  Crypto_Algo.SHA2_512:
            Cipher = SHA512
        elif self.CsmAlgo ==  Crypto_Algo.SHA2_512_224:
            Cipher = SHA512Hash(truncate="224")
        elif self.CsmAlgo ==  Crypto_Algo.SHA2_512_256:
            Cipher = SHA512Hash(truncate="256")
        elif self.CsmAlgo ==  Crypto_Algo.SHA3_224:
            Cipher = SHA3_224
        elif self.CsmAlgo ==  Crypto_Algo.SHA3_256:
            Cipher = SHA3_256
        elif self.CsmAlgo ==  Crypto_Algo.SHA3_384:
            Cipher = SHA3_384
        elif self.CsmAlgo ==  Crypto_Algo.SHA3_512:
            Cipher = SHA3_512
        elif self.CsmAlgo == Crypto_Algo.BLAKE_2s_512:
            Cipher = BLAKE2s.new(digest_bits=512)
        elif self.CsmAlgo == Crypto_Algo.BLAKE_2s_256:
            Cipher = BLAKE2s.new(digest_bits=256)
        elif self.CsmAlgo == Crypto_Algo.SHAKE128:
            Cipher = SHAKE128
        elif self.CsmAlgo == Crypto_Algo.SHAKE256:
            Cipher = SHAKE256

        if self.CsmAlgoMode == Crypto_Mode.CMAC:
            mac = CMAC.new(self._symmetric_key, ciphermod=Cipher)
            mac.update(Authenticator_Raw)
            return mac.digest()

        elif self.CsmAlgoMode == Crypto_Mode.HMAC:
            mac = HMAC.new(self._symmetric_key, digestmod=Cipher)
            mac.update(Authenticator_Raw)
            return mac.digest()

        # Currently only the following Modes are implemented: AES + CMAC and
        # All SHA-Hashes, BLAKE2s_256/512,  SHAKE128/256 + HMAC


        Exception("MAC Generation with " + str(self.CsmAlgo) + " and " + str(self.CsmAlgoMode) + " is not implemented yet")

    def Csm_MacVerify(self, Data_ID: bytes, I_PDU:bytes, FreshnessValue: bytes, Authenticator: bytes, AuthenticatorLength: int):
        #        Allowed_CsmAlgo = [Crypto_Algo._3DES, Crypto_Algo.AES, Crypto_Algo.BLAKE_1_256, Crypto_Algo.BLAKE_1_512,
        #                           Crypto_Algo.BLAKE_2s_256, Crypto_Algo.BLAKE_2s_512, Crypto_Algo.CHACHA, Crypto_Algo.CUSTOM,
        #                           Crypto_Algo.RIPEMD160, Crypto_Algo.RNG, Crypto_Algo.SHA1, Crypto_Algo.SHA1,
        #                           Crypto_Algo.SHA2_224, Crypto_Algo.SHA2_256, Crypto_Algo.SHA2_384, Crypto_Algo.SHA2_512,
        #                           Crypto_Algo.SHA2_512_224, Crypto_Algo.SHA2_512_256, Crypto_Algo.SHA3_224,
        #                           Crypto_Algo.SHA3_256, Crypto_Algo.SHA3_384, Crypto_Algo.SHA3_512]
        #
        #        Allowed_CsmAlgoModes = [Crypto_Mode.CMAC, Crypto_Mode.CTRDRBG, Crypto_Mode.CUSTOM, Crypto_Mode.GMAC,
        #                                Crypto_Mode.HMAC, Crypto_Mode.NOT_SET, Crypto_Mode.SIPHASH_2_4, Crypto_Mode.SIPHASH_4_8]

        Cipher = None
        Authenticator_Raw = b"".join([Data_ID, I_PDU, FreshnessValue])
        Authentic_Authenticator = None
        if self.CsmAlgo == Crypto_Algo.AES:
            Cipher = AES
        elif self.CsmAlgo == Crypto_Algo.SHA1:
            Cipher = SHA1
        elif self.CsmAlgo == Crypto_Algo.SHA2_224:
            Cipher = SHA224
        elif self.CsmAlgo == Crypto_Algo.SHA2_256:
            Cipher = SHA256
        elif self.CsmAlgo == Crypto_Algo.SHA2_384:
            Cipher = SHA384
        elif self.CsmAlgo == Crypto_Algo.SHA2_512:
            Cipher = SHA512
        elif self.CsmAlgo == Crypto_Algo.SHA2_512_224:
            Cipher = SHA512Hash(truncate="224")
        elif self.CsmAlgo == Crypto_Algo.SHA2_512_256:
            Cipher = SHA512Hash(truncate="256")
        elif self.CsmAlgo == Crypto_Algo.SHA3_224:
            Cipher = SHA3_224
        elif self.CsmAlgo == Crypto_Algo.SHA3_256:
            Cipher = SHA3_256
        elif self.CsmAlgo == Crypto_Algo.SHA3_384:
            Cipher = SHA3_384
        elif self.CsmAlgo == Crypto_Algo.SHA3_512:
            Cipher = SHA3_512
        elif self.CsmAlgo == Crypto_Algo.BLAKE_2s_512:
            Cipher = BLAKE2s.new(digest_bits=512)
        elif self.CsmAlgo == Crypto_Algo.BLAKE_2s_256:
            Cipher = BLAKE2s.new(digest_bits=256)
        elif self.CsmAlgo == Crypto_Algo.SHAKE128:
            Cipher = SHAKE128
        elif self.CsmAlgo == Crypto_Algo.SHAKE256:
            Cipher = SHAKE256

        if self.CsmAlgoMode == Crypto_Mode.CMAC:
            mac = CMAC.new(self._symmetric_key, ciphermod=Cipher)
            mac.update(Authenticator_Raw)
            Authentic_Authenticator = mac.digest()

        elif self.CsmAlgoMode == Crypto_Mode.HMAC:
            mac = HMAC.new(self._symmetric_key, digestmod=Cipher)
            mac.update(Authenticator_Raw)
            Authentic_Authenticator = mac.digest()

        if Authentic_Authenticator != None:
            # To-Do: Look at Scapy internal bit and byte implementation and try to create truncation with this

        Exception("MAC Verification with " + str(self.CsmAlgo) + " and " + str(self.CsmAlgoMode) + " is not implemented yet")

    def Csm_SignatureGenerate(self):
        # Asymmetric isn't implemented  at all yet
        Exception("Not implemented yet")

    def Csm_SignatureVerify(self):
        # Asymmetric isn't implemented  at all yet
        Exception("Not implemented yet")

    def Csm_KeyElementSet(self, symmetric_key: bytes, ):
        Exception("Not implemented yet")

    def Csm_KeySetVelid(self):
        Exception("Not implemented yet")

# Represents a Secured I-PDU
class SecOC(Packet):
    header: bytes                   # Secured I-PDU Header (optional)
    payload: bytes                  # Authentic I-PDU
    freshness: bytes                # Freshness Value (optional)
    authenticator: bytes            # Authenticator

class SecOC_Profile(Enum):
    Profile1 = 0x01 # 24Bit_CMAC_8Bit_FV
    Profile2 = 0x02 # 24Bit_CMAC_No_FV
    Profile3 = 0x03 # JASPAR, Recommended for CAN-bus use

class SecOCSocket(StreamSocket):
    authenticator_length: int = 0  # Length of authenticator represented in the Packet (bits)
    freshness_override_state: bool = false  # Should the freshness value be sent/received without checking
    FM: FreshnessValueManager = FreshnessValueManager()
    CSM: CryptoServiceManager = CryptoServiceManager()

    def __init__(self,
                 Symmetric_Key: bytes = None,
                 Asymmetric_Encryption_Key: bytes = None,
                 Asymmetric_Decryption_Key: bytes = None,
                 Profile: SecOC_Profile = SecOC_Profile.Profile3_JASPAR ):
        if Profile == SecOC_Profile.Profile1:
            self.CSM.CsmAlgo = Crypto_Algo.AES
            self.CSM.CsmAlgoMode = Crypto_Mode.CMAC
            self.CSM.CsmSecondaryAlgo = Crypto_Algo.NOT_SET
            self.FM.FM_Length = None
            self.FM.FM_TruncatedLength = 8
            self.authenticator_length = 24

        elif Profile == SecOC_Profile.Profile2:
            self.CSM.CsmAlgo = Crypto_Algo.AES
            self.CSM.CsmAlgoMode = Crypto_Mode.CMAC
            self.CSM.CsmSecondaryAlgo = Crypto_Algo.NOT_SET
            self.FM.FM_Length = 0
            self.FM.FM_TruncatedLength = 0
            self.authenticator_length = 24

        elif Profile == SecOC_Profile.Profile3:
            self.CSM.CsmAlgo = Crypto_Algo.AES
            self.CSM.CsmAlgoMode = Crypto_Mode.CMAC
            self.CSM.CsmSecondaryAlgo = Crypto_Algo.NOT_SET
            self.FM.FM_Length = 64
            self.FM.FM_TruncatedLength = 4
            self.authenticator_length = 24

        def __init__(self,
                     AuthenticatorLength: int,
                     CsmAlgo: Crypto_Algo,
                     FM_Mode: FreshnessModes,
                     FM_TruncatedLength: int,
                     FM_InitialValue: int = None,
                     FM_Length: int = None,
                     CsmAlgoMode: Crypto_Mode = Crypto_Mode.NOT_SET,
                     CsmSecondaryAlgo: Crypto_Algo = Crypto_Algo.NOT_SET,
                     Symmetric_Key: bytes = None,
                     Asymmetric_Encryption_Key: bytes = None,
                     Asymmetric_Decryption_Key: bytes = None):
            pass




#Errors:
# Freshness Value is still naive: Should be like on page 138 of AUTOSAR_SWS_SecureOnboardCommunication Specification
# Ciphers Enum should include a lot more ciphers as described in AUTOSAR_SWS_CryptoServiceManager
# Keys in SecOC Packet should be stored inside Crypto Service Manager

#Notes:
# All SecOC information are big-endian [PRS_SecOC_00101]
# The Secured I-PDU Header is the length of the Authentic I-PDU and itself can vary in length
# Freshness Values can also be already inside of payloads/Authentic I-PDUs
# Authenticator_raw = Data ID (16 bit, big endian) + Auth. I-PDU + Full Freshness Value (big endian)  (+ = concatinated)
# Authenticator = Authenticator_raw encrypted with the right cryptosystem to create a MAC/signature and than truncated to the required size
# [PRS_SecOc_00206] describes how to handle errors in the process of creating an authenticator. I don't think i should implement this.
# [PRS_SecOc_00213] There is an option to send Auth. I-PDU in one packet and data id. full freshness value in another package, to allow for full recreation of the authenticator
# [PRS_SecOc_00610], [PRS_SecOc_00620] and [PRS_SecOc_00630] define standard profiles (length of freshness, authenticator and used crypto)