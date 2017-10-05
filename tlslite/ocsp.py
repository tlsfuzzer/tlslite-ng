from .utils.asn1parser import ASN1Parser

class OCSPRespStatus:
    """ OCSP response status codes (RFC 2560) """
    successful = 0
    malformedRequest = 1
    internalError = 2
    tryLater = 3    # 4 is not used to match RFC2560 specification
    sigRequired = 5
    unauthorized = 6


class CertStatus:
    """ Certificate status in an OCSP response """
    good, revoked, unknown = range(3)


class SingleResponse(object):
    """ This class represents SingleResponse ASN1 type (defined in RFC2560) """
    def __init__(self, hashAlgorithm=None, issuerNameHash=None, \
                issuerKeyHash=None, serialNumber=None, status=None, \
                thisUpdate=None, nextUpdate=None, parser=None):
        if parser is not None:
            count = parser.getChildCount()
            certID = parser.getChild(0)
            self.certHashAlgorithm = certID.getChild(0)
            self.certIssuerNameHash = certID.getChild(1)
            self.certIssuerNameHash = certID.getChild(2)
            self.certSerialNumber = certID.getChild(3)
            self.certStatus = parser.getChild(1).value
            self.thisUpdate = parser.getChild(2).value
            # nextUpdate is optional
            try:
                fld = parser.getChild(3)
                if fld.type.tagId == 0:
                    self.nextUpdate = fld.value
            except SyntaxError:
                self.nextUpdate = None
        else:
            self.certHashAlgorithm = hashAlgorithm
            self.certIssuerNameHash = issuerNameHash
            self.certIssuerKeyHash = issuerKeyHash
            self.certSerialNumber = serialNumber
            self.certStatus = status
            self.thisUpdate = thisUpdate
            self.nextUpdate = nextUpdate


class OCSPResponse(object):
    """ This class represents an OCSP response. """
    def __init__(self):
        self.responseStatus = None
        self.responseType = None
        
        self.version = 1
        self.responderID = None
        self.producedAt = None
        self.responses = []
        
        self.signatureAlgorithm = None
        self.signature = None
        self.certs = []
        
    def parse(self, bytes):
        """
        Parse a DER-encoded OCSP response.

        :type bytes: stream of bytes
        :param bytes: An DER-encoded OCSP response
        """
        bytes = bytearray(bytes)
        p = ASN1Parser(bytes)

        responseStatus = p.getChild(0)
        self.responseStatus = responseStatus.value[0]
        # if the response status is not successsful, abort parsing other fields
        if self.responseStatus != OCSPRespStatus.successful:
            return self
        
        responseBytes = p.getChild(1).getChild(0)
        responseType = responseBytes.getChild(0)
        response = responseBytes.getChild(1)
        self.responseType = responseType.value
        # check if response is id-pkix-ocsp-basic
        if list(self.responseType) != [43, 6, 1, 5, 5, 7, 48, 1, 1]:
            raise SyntaxError()
        
        tbsResponseData = response.getChild(0).getChild(0)
        # test if version is ommited
        fld =  tbsResponseData.getChild(0)
        cnt = 0
        if (fld.type.tagId == 0):
            # version is not omitted
            cnt += 1
            self.version = tbsResponseData.getChild(0).value
        self.responderID = tbsResponseData.getChild(cnt).value
        self.producedAt = tbsResponseData.getChild(cnt+1).value
        
        responses = tbsResponseData.getChild(cnt+2)
        responsesCnt = responses.getChildCount()
        for i in range(responsesCnt):
            resp = responses.getChild(i)
            parsedResp = SingleResponse(parser=resp)
            self.responses.append(parsedResp)
        
        self.signatureAlgorithm = response.getChild(0).getChild(1).getChild(0)
        self.signature = response.getChild(0).getChild(2)
        
        try:
            # try if certs field is present
            certs = response.getChild(0).getChild(3)
            certsCnt = certs.getChildCount()
            for i in range(certsCnt):
                certificate = certs.getChild(i).getChild(0)
                tbsCertificate = certificate.getChild(0)
                signatureAlgorithm = certificate.getChild(1).getChild(0)
                signatureValue = certificate.getChild(2)
        except SyntaxError:
            self.certs = None

        return self
