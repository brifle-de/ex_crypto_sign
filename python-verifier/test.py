from lxml import etree
from signxml import XMLSigner, XMLVerifier
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa, utils
import base64
import struct

def canonicalize_xml_from_file(file_path):
    parser = etree.XMLParser(remove_blank_text=False)
    with open(file_path, 'rb') as f:
        xml_doc = etree.parse(f, parser)
    sub_element = xml_doc.xpath("//ds:SignedInfo", namespaces={
  'ds': 'http://www.w3.org/2000/09/xmldsig#',
  })
    canonical_xml = etree.tostring(sub_element[0], method="c14n", exclusive=True)
    return canonical_xml


def long_to_bytes(n, blocksize=0):
    """long_to_bytes(n:long, blocksize:int) : string
    Convert a long integer to a byte string.

    If optional blocksize is given and greater than zero, pad the front of the
    byte string with binary zeros so that the length is a multiple of
    blocksize.
    """
    # after much testing, this algorithm was deemed to be the fastest
    s = b""
    pack = struct.pack
    while n > 0:
        s = pack(b">I", n & 0xFFFFFFFF) + s
        n = n >> 32
    # strip off leading zeros
    for i in range(len(s)):
        if s[i] != b"\000"[0]:
            break
    else:
        # only happens when n == 0
        s = b"\000"
        i = 0
    s = s[i:]
    # add back some pad bytes.  this could be done more efficiently w.r.t. the
    # de-padding being done above, but sigh...
    if blocksize > 0 and len(s) % blocksize:
        s = (blocksize - len(s) % blocksize) * b"\000" + s
    return s


with open("ca.pem", "rb") as fh:
    ca_pem = fh.read()


# der encoded 
der = base64.b64decode("MEUCIClGDir64VXu61x9oovMPTEYTPk2RodOeAw5pcoYZA9jAiEA4fMxosxQG4m/ZRgSpwCN317yYyo3CtdrsX1VD0XL5IM=")
# encode to raw
(r, s) = raw = utils.decode_dss_signature(der)
int_len = 32
#print(raw)
signature = long_to_bytes(r, blocksize=int_len) + long_to_bytes(s, blocksize=int_len)
signature_base64 = base64.b64encode(signature).decode("utf-8")
#print(signature_base64)

cert = open("cert.pem").read()
key = open("priv.pem").read()
ca_pem_file = "./ca.pem"
data_to_sign = open("./debug/can_info.xml").read()
root = etree.fromstring(data_to_sign)
#signed_root = XMLSigner(signature_algorithm="ecdsa-sha256").sign(root, key=key, cert=cert)
#verified_data = XMLVerifier().verify(signed_root, ca_pem_file=ca_pem_file).signed_xml

signed_root = open('./debug/test-export.xml').read()
verified_data = XMLVerifier().verify(signed_root, ca_pem_file=ca_pem_file).signed_xml



verifier = XMLVerifier() 
#verified_data = verifier.verify(signed_root, x509_cert=ca_pem).signed_xml
prefix_map = {
    'ds': 'http://www.w3.org/2000/09/xmldsig#'
}


