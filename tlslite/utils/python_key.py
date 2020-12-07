

from .python_rsakey import Python_RSAKey
from .pem import dePem, pemSniff
from .asn1parser import ASN1Parser
from .cryptomath import bytesToNumber


class Python_Key(object):
    """
    Generic methods for parsing private keys from files.

    Handles both RSA and ECDSA keys, irrespective of file format.
    """

    @staticmethod
    def parsePEM(s, passwordCallback=None):
        """Parse a string containing a PEM-encoded <privateKey>."""

        if pemSniff(s, "PRIVATE KEY"):
            bytes = dePem(s, "PRIVATE KEY")
            return Python_Key._parse_pkcs8(bytes)
        elif pemSniff(s, "RSA PRIVATE KEY"):
            bytes = dePem(s, "RSA PRIVATE KEY")
            return Python_Key._parse_ssleay(bytes)
        elif pemSniff(s, "DSA PRIVATE KEY"):
            raise SyntaxError("DSA private key files unsupported")
        elif pemSniff(s, "EC PRIVATE KEY"):
            raise SyntaxError("ECDSA private key files unsupported")
        elif pemSniff(s, "PUBLIC KEY"):
            bytes = dePem(s, "PUBLIC KEY")
            return Python_Key._parse_public_key(bytes)
        else:
            raise SyntaxError("Not a PEM private key file")

    @staticmethod
    def _parse_public_key(bytes):
        # public keys are encoded as the subject_public_key_info objects
        spk_info = ASN1Parser(bytes)

        # first element of the SEQUENCE is the AlgorithmIdentifier
        alg_id = spk_info.getChild(0)

        # AlgId has two elements, the OID of the algorithm and parameters
        # parameters generally have to be NULL, with exception of RSA-PSS

        alg_oid = alg_id.getChild(0)

        if list(alg_oid.value) != [42, 134, 72, 134, 247, 13, 1, 1, 1]:
            raise SyntaxError("Only RSA Public keys supported")

        subject_public_key = ASN1Parser(
            ASN1Parser(spk_info.getChildBytes(1)).value[1:])

        modulus = subject_public_key.getChild(0)
        exponent = subject_public_key.getChild(1)

        n = bytesToNumber(modulus.value)
        e = bytesToNumber(exponent.value)

        return Python_RSAKey(n, e)

    @staticmethod
    def _parse_pkcs8(bytes):
        parser = ASN1Parser(bytes)

        # first element in PrivateKeyInfo is an INTEGER
        version = parser.getChild(0).value
        if bytesToNumber(version) != 0:
            raise SyntaxError("Unrecognized PKCS8 version")

        # second element in PrivateKeyInfo is a SEQUENCE of type
        # AlgorithmIdentifier
        alg_ident = parser.getChild(1)
        seq_len = alg_ident.getChildCount()
        # first item of AlgorithmIdentifier is an OBJECT (OID)
        oid = alg_ident.getChild(0)
        if list(oid.value) == [42, 134, 72, 134, 247, 13, 1, 1, 1]:
            key_type = "rsa"
        elif list(oid.value) == [42, 134, 72, 134, 247, 13, 1, 1, 10]:
            key_type = "rsa-pss"
        else:
            raise SyntaxError("Unrecognized AlgorithmIdentifier: {0}"
                              .format(list(oid.value)))
        # second item of AlgorithmIdentifier are parameters (defined by
        # above algorithm)
        if key_type == "rsa":
            if seq_len != 2:
                raise SyntaxError("Missing parameters for RSA algorithm ID")
            parameters = alg_ident.getChild(1)
            if parameters.value != bytearray(0):
                raise SyntaxError("RSA parameters are not NULL")
        else:  # rsa-pss
            pass  # ignore parameters - don't apply restrictions

        if seq_len > 2:
            raise SyntaxError("Invalid encoding of AlgorithmIdentifier")

        #Get the privateKey
        private_key_parser = parser.getChild(2)

        #Adjust for OCTET STRING encapsulation
        private_key_parser = ASN1Parser(private_key_parser.value)

        return Python_Key._parse_asn1_private_key(private_key_parser)

    @staticmethod
    def _parse_ssleay(data):
        """
        Parse binary structure of the old SSLeay file format used by OpenSSL.

        For RSA keys.
        """
        private_key_parser = ASN1Parser(data)
        return Python_Key._parse_asn1_private_key(private_key_parser)

    @staticmethod
    def _parse_asn1_private_key(private_key_parser):
        version = private_key_parser.getChild(0).value[0]
        if version != 0:
            raise SyntaxError("Unrecognized RSAPrivateKey version")
        n = bytesToNumber(private_key_parser.getChild(1).value)
        e = bytesToNumber(private_key_parser.getChild(2).value)
        d = bytesToNumber(private_key_parser.getChild(3).value)
        p = bytesToNumber(private_key_parser.getChild(4).value)
        q = bytesToNumber(private_key_parser.getChild(5).value)
        dP = bytesToNumber(private_key_parser.getChild(6).value)
        dQ = bytesToNumber(private_key_parser.getChild(7).value)
        qInv = bytesToNumber(private_key_parser.getChild(8).value)
        return Python_RSAKey(n, e, d, p, q, dP, dQ, qInv)
