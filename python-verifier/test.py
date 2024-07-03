from lxml import etree
from signxml import XMLSigner, XMLVerifier, SignatureConfiguration
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa, utils
import base64
import struct


with open("ca.pem", "rb") as fh:
    ca_pem = fh.read()




ca_pem_file = "./ca.pem"
signed_root = open('./debug/test-export.xml').read()
config = SignatureConfiguration(
    expect_references=3,
)

verified_data = XMLVerifier().verify(signed_root, ca_pem_file=ca_pem_file, expect_config=config)

# iterate over the references
for reference in verified_data:
    print(reference.signed_xml)
    




