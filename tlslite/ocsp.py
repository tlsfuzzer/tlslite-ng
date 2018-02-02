"""Class for handling primary OCSP responses"""

from .utils.asn1parser import ASN1Parser

class OCSPRespStatus(object):
    """ OCSP response status codes (RFC 2560) """
    successful = 0
    malformedRequest = 1
    internalError = 2
    tryLater = 3    # 4 is not used to match RFC2560 specification
    sigRequired = 5
    unauthorized = 6


class CertStatus(object):
    """ Certificate status in an OCSP response """
    good, revoked, unknown = range(3)


class SingleResponse(object):
    """ This class represents SingleResponse ASN1 type (defined in RFC2560) """
    def __init__(self, value):
        self.value = value
        self.certHashAlgorithm = None
        self.certIssuerNameHash = None
        self.certIssuerKeyHash = None
        self.certSerialNumber = None
        self.certStatus = None
        self.thisUpdate = None
        self.nextUpdate = None
        self.parse(value)

    def parse(self, value):
        certID = value.getChild(0)
        self.certHashAlgorithm = certID.getChild(0).value
        self.certIssuerNameHash = certID.getChild(1).value
        self.certIssuerKeyHash = certID.getChild(2).value
        self.certSerialNumber = certID.getChild(3).value
        self.certStatus = value.getChild(1).value
        self.thisUpdate = value.getChild(2).value
        # nextUpdate is optional
        try:
            fld = value.getChild(3)
            if fld.type.tagId == 0:
                self.nextUpdate = fld.value
        except SyntaxError:
            self.nextUpdate = None


class OCSPResponse(object):
    """ This class represents an OCSP response. """
    def __init__(self, value):
        self.bytes = None
        self.responseStatus = None
        self.responseType = None
        self.version = None
        self.responderID = None
        self.producedAt = None
        self.responses = []
        self.signatureAlgorithm = None
        self.signature = None
        self.certs = []
        self.parse(value)

    def parse(self, value):
        """
        Parse a DER-encoded OCSP response.

        :type value: stream of bytes
        :param value: An DER-encoded OCSP response
        """
        self.bytes = bytearray(value)
        p = ASN1Parser(self.bytes)
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
        basicResponse = response.getChild(0)
        tbsResponseData = basicResponse.getChild(0)
        # test if version is ommited
        fld = tbsResponseData.getChild(0)
        cnt = 0
        if (fld.type.tagId == 0):
            # version is not omitted
            cnt += 1
            self.version = tbsResponseData.getChild(0).value
        else:
            self.version = 1
        self.responderID = tbsResponseData.getChild(cnt).value
        self.producedAt = tbsResponseData.getChild(cnt+1).value
        responses = tbsResponseData.getChild(cnt+2)
        responsesCnt = responses.getChildCount()
        for i in range(responsesCnt):
            resp = responses.getChild(i)
            parsedResp = SingleResponse(resp)
            self.responses.append(parsedResp)
        self.signatureAlgorithm = basicResponse.getChild(1).getChild(0).value
        self.signature = basicResponse.getChild(2).value
        print(list(self.signature))
        # test if certs field is present
        if (basicResponse.getChildCount() > 3):
            certs = basicResponse.getChild(3)
            certsCnt = certs.getChildCount()
            for i in range(certsCnt):
                certificate = certs.getChild(i).value
                self.certs.append(certificate)
        else:
            self.certs = None
