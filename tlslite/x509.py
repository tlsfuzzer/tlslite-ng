# Authors:
#   Trevor Perrin
#   Google - parsing subject field
#
# See the LICENSE file for legal information regarding use of this file.

"""Class representing an X.509 certificate."""

from ecdsa.keys import VerifyingKey

from tlslite.errors import TLSDecryptionFailed

from .utils.asn1parser import ASN1Parser
from .utils.cryptomath import *
from .utils.keyfactory import (
    _createPublicRSAKey,
    _create_public_ecdsa_key,
    _create_public_dsa_key,
    _create_public_eddsa_key,
)
from .utils.pem import *
from .utils.compat import compatHMAC, b2a_hex
from .constants import TLS_1_3_BRAINPOOL_SIG_SCHEMES, AlgorithmOID, RSA_PSS_OID, ExtensionType, \
    SignatureAlgorithm, HashAlgorithm, SignatureScheme
from .utils.ecc import curve_name_to_hash_name
from .errors import TLSIllegalParameterException

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
    :ivar certAlg: algorithm of the public key, "rsa" for RSASSA-PKCS#1 v1.5,
        "rsa-pss" for RSASSA-PSS, "ecdsa" for ECDSA
    """

    def __init__(self):
        """Create empty certificate object."""
        self.bytes = bytearray(0)
        self.serial_number = None
        self.subject_public_key = None
        self.publicKey = None
        self.subject = None
        self.certAlg = None
        self.sigalg = None
        self.issuer = None

    def __hash__(self):
        """Calculate hash of object."""
        return hash(bytes(self.bytes))

    def __eq__(self, other):
        """Compare other object for equality."""
        if not hasattr(other, "bytes"):
            return NotImplemented
        return self.bytes == other.bytes

    def __ne__(self, other):
        """Compare with other object for inequality."""
        if not hasattr(other, "bytes"):
            return NotImplemented
        return not self == other

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

    def parseBinary(self, cert_bytes):
        """
        Parse a DER-encoded X.509 certificate.

        :type bytes: L{str} (in python2) or L{bytearray} of unsigned bytes
        :param bytes: A DER-encoded X.509 certificate.
        """
        self.bytes = bytearray(cert_bytes)
        parser = ASN1Parser(self.bytes)

        # Get the SignatureAlgorithm
        signature_algorithm_identifier = parser.getChild(1)
        self.sigalg = bytes(signature_algorithm_identifier.getChildBytes(0))

        # Finally get the (hash, signature) pair coresponding to it
        # If it is rsa-pss we need to check the aditional parameters field
        # to extract the hash algorithm
        if self.sigalg == RSA_PSS_OID:
            sigalg_hash = signature_algorithm_identifier.getChild(1)
            sigalg_hash = bytes(sigalg_hash.getChild(0).value)
            self.sigalg = AlgorithmOID.oid[sigalg_hash]
        else:
            self.sigalg = AlgorithmOID.oid[self.sigalg]

        # Get the tbsCertificate
        tbs_certificate = parser.getChild(0)
        # Is the optional version field present?
        # This determines which index the key is at.
        if tbs_certificate.value[0] == 0xA0:
            serial_number_index = 1
            subject_public_key_info_index = 6
        else:
            serial_number_index = 0
            subject_public_key_info_index = 5

        # Get serial number
        self.serial_number = bytesToNumber(
            tbs_certificate.getChild(serial_number_index).value
        )

        # Get the issuer
        self.issuer = tbs_certificate.getChildBytes(
            subject_public_key_info_index - 3)

        # Get the subject
        self.subject = tbs_certificate.getChildBytes(
            subject_public_key_info_index - 1)

        # Get the subjectPublicKeyInfo
        subject_public_key_info = tbs_certificate.getChild(
            subject_public_key_info_index)

        # Get the AlgorithmIdentifier
        alg_identifier = subject_public_key_info.getChild(0)
        alg_identifier_len = alg_identifier.getChildCount()

        self.certAlg = get_algorithm(alg_identifier)

        # for RSA the parameters of AlgorithmIdentifier shuld be a NULL
        if self.certAlg == "rsa":
            if alg_identifier_len != 2:
                raise SyntaxError("Missing parameters in AlgorithmIdentifier")
            params = alg_identifier.getChild(1)
            if params.value != bytearray(0):
                raise SyntaxError(
                    "Unexpected non-NULL parameters in "
                    "AlgorithmIdentifier"
                )
        elif self.certAlg == "ecdsa":
            self.publicKey = _ecdsa_pubkey_parsing(
                tbs_certificate.getChildBytes(subject_public_key_info_index)
            )
            return
        elif self.certAlg == "dsa":
            self.publicKey = _dsa_pubkey_parsing(subject_public_key_info)
            return
        elif self.certAlg == "Ed25519" or self.certAlg == "Ed448":
            self.publicKey = _eddsa_pubkey_parsing(
                tbs_certificate.getChildBytes(subject_public_key_info_index)
            )
            return
        else:  # rsa-pss
            pass  # ignore parameters, if any - don't apply key restrictions

        self.publicKey, self.subject_public_key = _rsa_pubkey_parsing(
            subject_public_key_info, self.certAlg
        )

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


def get_algorithm(alg_identifier):
    """
    Rethrive the algoritm from the AlgorithmIdentifier
    """
    # first item of AlgorithmIdentifier is the algorithm
    alg = alg_identifier.getChild(0)
    alg_oid = alg.value
    if list(alg_oid) == [42, 134, 72, 134, 247, 13, 1, 1, 1]:
        return "rsa"
    elif list(alg_oid) == [42, 134, 72, 134, 247, 13, 1, 1, 10]:
        return "rsa-pss"
    elif list(alg_oid) == [42, 134, 72, 206, 56, 4, 1]:
        return "dsa"
    elif list(alg_oid) == [42, 134, 72, 206, 61, 2, 1]:
        return "ecdsa"
    elif list(alg_oid) == [43, 101, 112]:
        return "Ed25519"
    elif list(alg_oid) == [43, 101, 113]:
        return "Ed448"
    else:
        raise SyntaxError("Unrecognized AlgorithmIdentifier")

def _eddsa_pubkey_parsing(subject_public_key_info):
    """
    Convert the raw DER encoded EdDSA parameters into public key object.

    :param subject_public_key_info: bytes like object with the DER encoded
        public key in it
    """
    try:
        # python ecdsa knows how to parse curve OIDs so re-use that
        # code
        public_key = VerifyingKey.from_der(compatHMAC(subject_public_key_info))
    except Exception:
        raise SyntaxError("Malformed or unsupported public key in "
                          "certificate")
    return _create_public_eddsa_key(public_key)

def _rsa_pubkey_parsing(subject_public_key_info, cert_alg):
    """
    Parse the RSA public key from the certificate.

    :param subject_public_key_info: ASN1Parser object with subject
        public key info of X.509 certificate
    """

    # Get the subjectPublicKey
    subject_public_key = subject_public_key_info.getChild(1)
    self_subject_public_key = subject_public_key_info.getChildBytes(1)
    self_subject_public_key = ASN1Parser(self_subject_public_key).value[1:]

    # Adjust for BIT STRING encapsulation
    if subject_public_key.value[0]:
        raise SyntaxError()
    subject_public_key = ASN1Parser(subject_public_key.value[1:])

    # Get the modulus and exponent
    modulus = subject_public_key.getChild(0)
    public_exponent = subject_public_key.getChild(1)

    # Decode them into numbers
    # pylint: disable=invalid-name
    # 'n' and 'e' are the universally used parameters in RSA algorithm
    # definition
    n = bytesToNumber(modulus.value)
    e = bytesToNumber(public_exponent.value)

    # Create a public key instance
    public_key = _createPublicRSAKey(n, e, cert_alg)

    return public_key, self_subject_public_key
    # pylint: enable=invalid-name

def _ecdsa_pubkey_parsing(subject_public_key_info):
    """
    Convert the raw DER encoded ECDSA parameters into public key object

    :param subject_public_key_info: bytes like object with DER encoded
        public key in it
    """
    try:
        # python ecdsa knows how to parse curve OIDs so re-use that
        # code
        public_key = VerifyingKey.from_der(compatHMAC(subject_public_key_info))
    except Exception:
        raise SyntaxError("Malformed or unsupported public key in "
                          "certificate")
    # pylint: disable=invalid-name
    x = public_key.pubkey.point.x()
    y = public_key.pubkey.point.y()
    curve_name = public_key.curve.name
    return _create_public_ecdsa_key(x, y, curve_name)
    # pylint: enable=invalid-name

def _dsa_pubkey_parsing(subject_public_key_info):
    """
    Convert the raw DER encoded DSA parameters into public key object

    :param subject_public_key_info: bytes like object with DER encoded
      global parameters and public key in it
    """
    global_parameters = (subject_public_key_info.getChild(0)).getChild(1)
    # Get the subjectPublicKey
    public_key = subject_public_key_info.getChild(1)

    # Adjust for BIT STRING encapsulation and get hex value
    if public_key.value[0]:
        raise SyntaxError()
    # pylint: disable=invalid-name
    y = ASN1Parser(public_key.value[1:])

    # Get the {A, p, q}
    p = global_parameters.getChild(0)
    q = global_parameters.getChild(1)
    g = global_parameters.getChild(2)

    # Decode them into numbers
    y = bytesToNumber(y.value)
    p = bytesToNumber(p.value)
    q = bytesToNumber(q.value)
    g = bytesToNumber(g.value)

    # Create a public key instance
    return _create_public_dsa_key(p, q, g, y)
    # pylint: enable=invalid-name


class Credential(object):
    """
    This class represents a credential.

    :vartype valid_time: int
    :ivar valid_time: time, after which the delegated
      credential is no longer valid.

    :vartype dc_cert_verify_algorithm: tuple(int,int)
    :ivar dc_cert_verify_algorithm: the signature algorithm of the credential
      key pair.

    :vartype subject_public_key_info: bytearray (ASN1_subjectPublicKeyInfo)
    :ivar subject_public_key_info: the credential's public key, a DER-
      encoded.
    """

    def __init__(
            self, valid_time=0,
            dc_cert_verify_algorithm=None,
            subject_public_key_info=None,
            bytes=None
    ):
        """Create empty credential object."""
        self.valid_time = valid_time
        self.dc_cert_verify_algorithm = dc_cert_verify_algorithm
        self.subject_public_key_info = subject_public_key_info
        self.bytes = bytes
        self.subject_public_key = None
        self.pub_key_alg = None
        self.pub_key = None

    def parse_pub_key(self):
        """
        Parse a DER-encoded [X.690] SubjectPublicKeyInfo
        to extract public key
        """
        parser = ASN1Parser(self.subject_public_key_info)
        alg_identifier = parser.getChild(0)
        alg_identifier_len = parser.getChildCount()

        self.pub_key_alg = get_algorithm(alg_identifier)

        if self.pub_key_alg == "rsa":
            if alg_identifier_len != 2:
                raise SyntaxError("Missing parameters in AlgorithmIdentifier")
            params = alg_identifier.getChild(1)
            if params.value != bytearray(0):
                raise SyntaxError(
                    "Unexpected non-NULL parameters in "
                    "AlgorithmIdentifier"
                )
        elif self.pub_key_alg == "ecdsa":
            self.pub_key = _ecdsa_pubkey_parsing(self.subject_public_key_info)
            return
        elif self.pub_key_alg == "dsa":
            self.pub_key = _dsa_pubkey_parsing(parser)
            return
        elif self.pub_key_alg == "Ed25519" or self.pub_key_alg == "Ed448":
            self.pub_key = _eddsa_pubkey_parsing(
                self.subject_public_key_info
            )
            return
        else:
            pass
        self.pub_key, self.subject_public_key = _rsa_pubkey_parsing(
            parser,
            self.pub_key_alg)

    @staticmethod
    def marshal(valid_time, dc_cert_verify_algorithm, subject_public_key_info):
        """
        Encode the credential raw bytes.

        :vartype valid_time: int
        :ivar valid_time: time, after which the delegated
            credential is no longer valid.

        :vartype dc_cert_verify_algorithm: tuple(int,int)
        :ivar dc_cert_verify_algorithm: the signature algorithm of the credential
            key pair.

        :vartype subject_public_key_info: bytearray (ASN1_subjectPublicKeyInfo)
        :ivar subject_public_key_info: the credential's public key, a DER-
            encoded.

        """
        cred_writer = Writer()
        cred_writer.addFour(valid_time)
        cred_writer.addOne(dc_cert_verify_algorithm[0])
        cred_writer.addOne(dc_cert_verify_algorithm[1])
        cred_writer.add_var_bytes(subject_public_key_info, 3)
        return cred_writer.bytes

class DelegatedCredential(object):
    """
    This class represents a delegated credential.

    :vartype cred: Credential
    :ivar cred: the credential structure

    :vartype algorithm: tuple(int,int)
    :ivar algorithm: The signature algorithm used to create
      DelegatedCredential.signature.

    :vartype signature: bytearray
    :ivar signature: The delegation, a signature that binds the credential to
      the end-entity certificate's public key.
    """

    def __init__(self, cred=None, algorithm=None,
                 signature=None):
        """Create empty credential object."""
        self.cred = cred
        self.algorithm = algorithm
        self.signature = signature

    def parse(self, parser):
        """Parsing Delegating Credendial."""
        valid_time = parser.get(4)
        dc_cert_verify_algorithm = (parser.get(1), parser.get(1))
        subject_public_key_info = parser.getVarBytes(3)
        cred_raw_bytes = Credential.marshal(valid_time,
                                            dc_cert_verify_algorithm,
                                            subject_public_key_info)
        self.cred = Credential(
            valid_time=valid_time,
            dc_cert_verify_algorithm=dc_cert_verify_algorithm,
            subject_public_key_info=subject_public_key_info,
            bytes=cred_raw_bytes
        )

        self.cred.parse_pub_key()

        self.algorithm = (parser.get(1), parser.get(1))
        self.signature = parser.getVarBytes(2)
        return self

    def write(self):
        """Serialise object to a DER encoded string."""
        writer = Writer()
        writer.addFour(
            self.cred.valid_time)
        writer.addOne(
            self.cred.dc_cert_verify_algorithm[0])
        writer.addOne(
            self.cred.dc_cert_verify_algorithm[1])
        writer.add_var_bytes(
            self.cred.subject_public_key_info, 3)
        writer.addOne(self.algorithm[0])
        writer.addOne(self.algorithm[1])
        writer.add_var_bytes(self.signature, 2)
        return writer.bytes

    def verify(self, certificate_entry, client_hello, cert_verify):
        """
        Verify that the delegated credential is valid.

        Checks if the the delegated credential did not expire,
        the algorithms are of a type advertized by the client,
        the verify alg matches the scheme in peer's message.
        """
        certificate = certificate_entry.certificate
        dc_sig_list = client_hello.getExtension(
            ExtensionType.delegated_credential)
        if self.cred.dc_cert_verify_algorithm not in dc_sig_list.sigalgs:
            raise TLSIllegalParameterException(
                "The dc_cert_verify_algorithm of the delegated "
                "credential algorithm must be a type "
                "advertised by the client in ClientHello extension.")

        sig_list = client_hello.getExtension(ExtensionType.signature_algorithms)
        if self.algorithm not in sig_list.sigalgs:
            raise TLSIllegalParameterException(
                "The algorithm field MUST be of a type advertised by "
                "the client in the signature_algorithms extension of "
                "the ClientHello message.")

        dc_cert_verify_algorithm = self.cred.dc_cert_verify_algorithm
        if dc_cert_verify_algorithm != cert_verify.signatureAlgorithm:
            raise TLSIllegalParameterException(
                "The dc_cert_verify_algorithm does not match "
                "the scheme indicated in the peer's "
                "CertificateVerify message")

        sig_context = DelegatedCredential.compute_certificate_dc_sig_context(
            certificate.bytes,
            self.cred.bytes,
            self.algorithm)

        cert_pub_key = certificate.publicKey
        sig_scheme = self.algorithm

        if sig_scheme in (SignatureScheme.ed25519,
                                SignatureScheme.ed448):
            pad_type = None
            hash_name = "intrinsic"
            salt_len = None
            method = cert_pub_key.hashAndVerify
        elif sig_scheme[1] == SignatureAlgorithm.ecdsa:
            pad_type = None
            hash_name = HashAlgorithm.toRepr(sig_scheme[0])
            matching_hash = curve_name_to_hash_name(
                cert_pub_key.curve_name)
            if hash_name != matching_hash:
                raise TLSIllegalParameterException(
                    "server selected signature method invalid for the "
                    "certificate it presented (curve mismatch)")

            salt_len = None
            method = cert_pub_key.hashAndVerify
        elif sig_scheme in TLS_1_3_BRAINPOOL_SIG_SCHEMES:
            scheme = SignatureScheme.toRepr(sig_scheme)
            pad_type = None
            hash_name = SignatureScheme.getHash(scheme)
            salt_len = None
            method = cert_pub_key.hashAndVerify
        else:
            scheme = SignatureScheme.toRepr(sig_scheme)
            pad_type = SignatureScheme.getPadding(scheme)
            hash_name = SignatureScheme.getHash(scheme)
            salt_len = getattr(hashlib, hash_name)().digest_size
            method = cert_pub_key.hashAndVerify
        if not method(self.signature,
                        sig_context,
                        pad_type,
                        hash_name,
                        salt_len):
            raise TLSDecryptionFailed("server Delegated Credential " \
            "signature verification failed.")

        return True

    @staticmethod
    def compute_certificate_dc_sig_context(cert_bytes, cred_bytes, dc_alg):
        """
        Reconstructs the certificate signature context
        over the delegated credential.
        """
        verify_bytes = bytearray(b'\x20' * 64 +
                                 b'TLS, server delegated credentials' +
                                 b'\x00' +
                                 cert_bytes +
                                 cred_bytes +
                                 bytearray(dc_alg))
        return verify_bytes
