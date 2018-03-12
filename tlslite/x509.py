# Authors: 
#   Trevor Perrin
#   Google - parsing subject field
#
# See the LICENSE file for legal information regarding use of this file.

"""Class representing an X.509 certificate."""

from .utils.asn1parser import ASN1Parser
from .utils.cryptomath import *
from .utils.keyfactory import _createPublicRSAKey
from .utils.pem import *


class X509(object):
    """
    This class represents an X.509 certificate.

    :vartype bytes: bytearray
    :ivar bytes: The DER-encoded ASN.1 certificate

    :vartype publicKey: ~tlslite.utils.rsakey.RSAKey
    :ivar publicKey: The subject public key from the certificate.

    :vartype subject: bytearray
    :ivar subject: The DER-encoded ASN.1 subject distinguished name.

    :vartype certAlg: str
    :ivar certAlg: algorithm of the public key, "rsa" for RSASSA-PKCS#1 v1.5
        and "rsa-pss" for RSASSA-PSS
    """

    def __init__(self):
        """Create empty certificate object."""
        self.bytes = bytearray(0)
        self.publicKey = None
        self.subject = None
        self.certAlg = None

    def parse(self, s):
        """
        Parse a PEM-encoded X.509 certificate.

        :type s: str
        :param s: A PEM-encoded X.509 certificate (i.e. a base64-encoded
            certificate wrapped with "-----BEGIN CERTIFICATE-----" and
            "-----END CERTIFICATE-----" tags).
        """
        bytes = dePem(s, "CERTIFICATE")
        self.parseBinary(bytes)
        return self

    def parseBinary(self, bytes):
        """
        Parse a DER-encoded X.509 certificate.

        :type bytes: str or L{bytearray} of unsigned bytes
        :param bytes: A DER-encoded X.509 certificate.
        """
        self.bytes = bytearray(bytes)
        p = ASN1Parser(self.bytes)

        #Get the tbsCertificate
        tbsCertificateP = p.getChild(0)

        #Is the optional version field present?
        #This determines which index the key is at.
        if tbsCertificateP.value[0]==0xA0:
            subjectPublicKeyInfoIndex = 6
        else:
            subjectPublicKeyInfoIndex = 5

        #Get the subject
        self.subject = tbsCertificateP.getChildBytes(\
                           subjectPublicKeyInfoIndex - 1)

        #Get the subjectPublicKeyInfo
        subjectPublicKeyInfoP = tbsCertificateP.getChild(\
                                    subjectPublicKeyInfoIndex)

        # Get the AlgorithmIdentifier
        algIdentifier = subjectPublicKeyInfoP.getChild(0)
        algIdentifierLen = algIdentifier.getChildCount()
        # first item of AlgorithmIdentifier is the algorithm
        alg = algIdentifier.getChild(0)
        rsaOID = alg.value
        if list(rsaOID) == [42, 134, 72, 134, 247, 13, 1, 1, 1]:
            self.certAlg = "rsa"
        elif list(rsaOID) == [42, 134, 72, 134, 247, 13, 1, 1, 10]:
            self.certAlg = "rsa-pss"
        else:
            raise SyntaxError("Unrecognized AlgorithmIdentifier")

        # for RSA the parameters of AlgorithmIdentifier should be a NULL
        if self.certAlg == "rsa":
            if algIdentifierLen != 2:
                raise SyntaxError("Missing parameters in AlgorithmIdentifier")
            params = algIdentifier.getChild(1)
            if params.value != bytearray(0):
                raise SyntaxError("Unexpected non-NULL parameters in "
                                  "AlgorithmIdentifier")
        else:  # rsa-pss
            pass  # ignore parameters, if any - don't apply key restrictions

        #Get the subjectPublicKey
        subjectPublicKeyP = subjectPublicKeyInfoP.getChild(1)

        #Adjust for BIT STRING encapsulation
        if (subjectPublicKeyP.value[0] !=0):
            raise SyntaxError()
        subjectPublicKeyP = ASN1Parser(subjectPublicKeyP.value[1:])

        #Get the modulus and exponent
        modulusP = subjectPublicKeyP.getChild(0)
        publicExponentP = subjectPublicKeyP.getChild(1)

        #Decode them into numbers
        n = bytesToNumber(modulusP.value)
        e = bytesToNumber(publicExponentP.value)

        #Create a public key instance
        self.publicKey = _createPublicRSAKey(n, e)

    def getFingerprint(self):
        """
        Get the hex-encoded fingerprint of this certificate.

        :rtype: str
        :returns: A hex-encoded fingerprint.
        """
        return b2a_hex(SHA1(self.bytes))

    def writeBytes(self):
        """Serialise object to a DER encoded string."""
        return self.bytes


