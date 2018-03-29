# Author: Anna Khaitovich (c) 2017
# see LICENCE file for legal information regarding use of this file

# compatibility with Python 2.6, for that we need unittest2 package,
# which is not available on 3.3 or 3.4
try:
    import unittest2 as unittest
except ImportError:
    import unittest

from tlslite.utils.compat import a2b_base64, b2a_hex
from tlslite.utils.asn1parser import ASN1Parser
from tlslite.x509 import X509
from tlslite.ocsp import OCSPResponse, OCSPRespStatus, SingleResponse

resp_OK = a2b_base64(str(
"MIIGQwoBAKCCBjwwggY4BgkrBgEFBQcwAQEEggYpMIIGJTCBv6IWBBScTQCZAA6LsAGBdaG68NAl"
"16AcRxgPMjAxNzExMTMxMzUxMTJaMG8wbTBFMAkGBSsOAwIaBQAEFAyeTZw97e+E2JHpcsfPhAa8"
"GXsHBBSW3mHxvRwWKVMcwMx9O4MAQOYafAIMEOb8YrdBitUAXkW2gAAYDzIwMTcxMTEzMTM1MTEy"
"WqARGA8yMDE3MTExNzEzNTExMlqhIzAhMB8GCSsGAQUFBzABAgQSBBCaJ3RKL6xdUzjZb2szrKTz"
"MA0GCSqGSIb3DQEBCwUAA4IBAQCb9exoMqi0HgERpQz50GQF6uO2Cs7Jxeajd1XSefnY+lVWZubl"
"UrPQTdBo5P5VjLgF9rgYzI8es7zwFLhPdzLmos8Sp5OjDD0z5NDqoRqSGQxEK7OQ48Bx8EoPtVfP"
"B4wr8tHbJtowaLYM5Jt1Nfmys9at1H+uq+NcrNvs+4HQEMZHUMk88k8wH3cPfdQCYJVk3faRnQyE"
"kAARX1Ytq2LGEtoK94nJTlwz+khJDtiyvg7fclBbfuM7LIVdligPBF8384yy7W8tifRow/NuMDv4"
"BgDHIA6I5PPSM5CZjGm5ur6Kia/LKvu8abw/31h/ufZH3SNk5XRh7dDUfscM2cSnoIIESzCCBEcw"
"ggRDMIIDK6ADAgECAgwaYEAHumSvQwbKFvowDQYJKoZIhvcNAQELBQAwZjELMAkGA1UEBhMCQkUx"
"GTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExPDA6BgNVBAMTM0dsb2JhbFNpZ24gT3JnYW5pemF0"
"aW9uIFZhbGlkYXRpb24gQ0EgLSBTSEEyNTYgLSBHMjAeFw0xNzEwMDkwNzU1MDRaFw0xODAxMDkw"
"NzU1MDRaMIGOMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEVMBMGA1UE"
"BRMMMjAxNzEwMDkwMDAyMU0wSwYDVQQDE0RHbG9iYWxTaWduIE9yZ2FuaXphdGlvbiBWYWxpZGF0"
"aW9uIENBIC0gU0hBMjU2IC0gRzIgLSBPQ1NQIFJlc3BvbmRlcjCCASIwDQYJKoZIhvcNAQEBBQAD"
"ggEPADCCAQoCggEBANJDl88wauPZUs7bp+veBYvXMBMiyGWoJt42J4pklvr6X6kKBRf1OPCRqln1"
"zrfBL53Jen+jLWhpr2sY4Ln9mq7tRLcUuaXV/P+D7XUXBj5oG8G5/FQyLpJ+D/EqO7/Wn3YdXqIh"
"ZOyo6vcMyvo4g3DaZaaibWXVFZQ+rO5WluGlbBMHu1AZNoZWgcVH5dM7WJsHf9y5/gYxMlUWKUTR"
"RShsZFHqDYc2N80QQKqdHRz9x2zwlBlBnj5s6fO9vN30bQXUZTvYsZOAt272fpCQV2KBP6KLZ0XV"
"jLiQmLmzYeBLTflGzhOCfYFxbztT5QQcYC/WEnOSmOuWNhz3jaFH62ECAwEAAaOBxzCBxDAdBgNV"
"HQ4EFgQUnE0AmQAOi7ABgXWhuvDQJdegHEcwHwYDVR0jBBgwFoAUlt5h8b0cFilTHMDMfTuDAEDm"
"GnwwDwYJKwYBBQUHMAEFBAIFADBMBgNVHSAERTBDMEEGCSsGAQQBoDIBXzA0MDIGCCsGAQUFBwIB"
"FiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAOBgNVHQ8BAf8EBAMCB4Aw"
"EwYDVR0lBAwwCgYIKwYBBQUHAwkwDQYJKoZIhvcNAQELBQADggEBADOlR5gacWfQOaRVrOaRAfEA"
"SZdVfyAXjubDTl4Z0/jXQCIhM7EJaCLpEKKDVkSb2TZZVNqYsegHs1kRVo9U6chXSRtG4JKKPCAy"
"kGw8MYyX5Eewu1JpKy/RqkbBBUDJS6pSj1LYwQxTb0JrfQbEddRBIexRYEZ+JXtqdOqpsV1R/4E/"
"k82y7fOo9N96hDrWZLF7h+p2Bg8og+eUD9kNNGPx2/iLfNYYUDynU4Ay3wOxRzb8MHTw7OpevlEN"
"GNUvcGYyOSWwMQHk8P0BCJZA8RpXuEkW/ep0ZSnNVMpbjtSpSE1i0OxMdKbfJTzm+l87FMXz/8oX"
"p+YNJ+UJfB6ALag="))
resp_malformed = a2b_base64("MAMKAQE=")
resp_internal = a2b_base64("MAMKAQI=")
resp_trylater = a2b_base64("MAMKAQM=")
resp_sigreq = a2b_base64("MAMKAQU=")
resp_unauthorized = a2b_base64("MAMKAQY=")
resp_nonext = a2b_base64(str(
"MIIBsAoBAKCCAakwggGlBgkrBgEFBQcwAQEEggGWMIIBkjB8ohYEFPW6BZQHpc7jISl5Z3Tq3X0p"
"dI9AGA8yMDE4MDExNzEzMzgyOVowUTBPMDowCQYFKw4DAhoFAAQUkBUkEUsQTCuZ8rp/mrdlULbf"
"yK4EFPW6BZQHpc7jISl5Z3Tq3X0pdI9AAgEBgAAYDzIwMTgwMTE3MTMzODI5WjANBgkqhkiG9w0B"
"AQUFAAOCAQEAgX46PdN6W6gLbOuWNwTHAwJ79agqjADHLtvYyISVCenKmaCMrhoe6jcutw1A4wz4"
"9BKfYqnO9AL1LYHOJ6ZPlzJx/nEiFue8HXb+ChiwG+nEhXprug+wP/APuKSOaKH2kcQf4Jtuv9cz"
"n/2PCaVmC+ErEThuGTZouT4eEIFMUGGDH+nZFHbl+DNm6R3+D7atOE1gDBO2LDJqIoZvaZTSpY+4"
"djZaiTdWAdOcUnnBhlhBvjg8nv6zxJ9ERBqm5P9cffnYVAJeGqylq/WFT/Ni6MprXgYoZq9bc7tk"
"PGGh5CnrOhcIQCUIX+ceM6ruxdraiPJALpY1gZz7SY53GQsXfg=="))

class TestOCSP(unittest.TestCase):
    def test___init__(self):
        resp = OCSPResponse(resp_OK)
        self.assertEqual(OCSPRespStatus.successful, resp.resp_status)
    
    def test_malformedrequest(self):
        resp = OCSPResponse(resp_malformed)
        self.assertEqual(OCSPRespStatus.malformedRequest, resp.resp_status)
    
    def test_internalerror(self):
        resp = OCSPResponse(resp_internal)
        self.assertEqual(OCSPRespStatus.internalError, resp.resp_status)

    def test_trylater(self):
        resp = OCSPResponse(resp_trylater)
        self.assertEqual(OCSPRespStatus.tryLater, resp.resp_status)

    def test_sigrequired(self):
        resp = OCSPResponse(resp_sigreq)
        self.assertEqual(OCSPRespStatus.sigRequired, resp.resp_status)

    def test_unauthorized(self):
        resp = OCSPResponse(resp_unauthorized)
        self.assertEqual(OCSPRespStatus.unauthorized, resp.resp_status)

    def test_type_id_pkix_ocsp_basic(self):
        resp = OCSPResponse(resp_OK)
        self.assertEqual(bytearray([43, 6, 1, 5, 5, 7, 48, 1, 1]), resp.resp_type)

    def test_resp_id(self):
        resp = OCSPResponse(resp_OK)
        self.assertEqual(bytearray([4, 20, 156, 77, 0, 153, 0, 14, 139, 176, 1, 129, 
                                    117, 161, 186, 240, 208, 37, 215, 160, 28, 71]), 
                        resp.resp_id)
    
    def test_produced_at(self):
        resp = OCSPResponse(resp_OK)
        self.assertEqual(bytearray(b"20171113135112Z"), resp.produced_at)

    def test_signature_alg(self):
        resp = OCSPResponse(resp_OK)
        self.assertEqual(bytearray([42, 134, 72, 134, 247, 13, 1, 1, 11]), resp.signature_alg)

    def test_signature(self):
        resp = OCSPResponse(resp_OK)
        self.assertEqual(
            bytearray([0, 155, 245, 236, 104, 50, 168, 180, 30, 1, 17, 165, 12, 249, 208,
            100, 5, 234, 227, 182, 10, 206, 201, 197, 230, 163, 119, 85, 210, 121, 249,
            216, 250, 85, 86, 102, 230, 229, 82, 179, 208, 77, 208, 104, 228, 254, 85,
            140, 184, 5, 246, 184, 24, 204, 143, 30, 179, 188, 240, 20, 184, 79, 119, 50,
            230, 162, 207, 18, 167, 147, 163, 12, 61, 51, 228, 208, 234, 161, 26, 146, 25,
            12, 68, 43, 179, 144, 227, 192, 113, 240, 74, 15, 181, 87, 207, 7, 140, 43,
            242, 209, 219, 38, 218, 48, 104, 182, 12, 228, 155, 117, 53, 249, 178, 179,
            214, 173, 212, 127, 174, 171, 227, 92, 172, 219, 236, 251, 129, 208, 16, 198,
            71, 80, 201, 60, 242, 79, 48, 31, 119, 15, 125, 212, 2, 96, 149, 100, 221,
            246, 145, 157, 12, 132, 144, 0, 17, 95, 86, 45, 171, 98, 198, 18, 218, 10,
            247, 137, 201, 78, 92, 51, 250, 72, 73, 14, 216, 178, 190, 14, 223, 114, 80,
            91, 126, 227, 59, 44, 133, 93, 150, 40, 15, 4, 95, 55, 243, 140, 178, 237,
            111, 45, 137, 244, 104, 195, 243, 110, 48, 59, 248, 6, 0, 199, 32, 14, 136,
            228, 243, 210, 51, 144, 153, 140, 105, 185, 186, 190, 138, 137, 175, 203, 42,
            251, 188, 105, 188, 63, 223, 88, 127, 185, 246, 71, 221, 35, 100, 229, 116,
            97, 237, 208, 212, 126, 199, 12, 217, 196, 167]), 
            resp.signature)

    def test_certs(self):
        resp = OCSPResponse(resp_OK)
        self.assertGreater(len(resp.certs), 0)
        cert = resp.certs[0]  # checking only first certificate
        self.assertIsInstance(cert, bytearray)
        x509 = X509()
        x509.parseBinary(cert)
        self.assertIsInstance(x509, X509)

class TestSingleResponse(unittest.TestCase):
    def test___init__(self):
        resp = OCSPResponse(resp_OK)
        singleRespList = resp.responses
        singleRespCnt = len(singleRespList)
        for i in range(singleRespCnt):
            singleResp = resp.responses[i]
            self.assertEqual(bytearray(), singleResp.cert_status)

    def test_nonextupdate(self):
        resp = OCSPResponse(resp_nonext)
        singleRespList = resp.responses
        singleRespCnt = len(singleRespList)
        for i in range(singleRespCnt):
            singleResp = resp.responses[i]
            self.assertEqual(bytearray(), singleResp.cert_status)
            self.assertEqual(None, singleResp.next_update)

if __name__ == '__main__':
    unittest.main()
