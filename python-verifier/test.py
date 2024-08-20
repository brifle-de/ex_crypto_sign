from lxml import etree
from signxml import XMLSigner, XMLVerifier, SignatureConfiguration
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa, utils
import base64
import struct






ca_pem_file = "./ca.pem"
#ca_pem_file = "./ca_test.pem"
#signed_root = open('./debug/export_sign.xml').read()
signed_root = open('./debug/test-export-large.xml').read()
config = SignatureConfiguration(
   #  expect_references=3,
     expect_references=2,
)

verified_data = XMLVerifier().verify(signed_root, ca_pem_file=ca_pem_file, expect_config=config)

# iterate over the references
for reference in verified_data:
    print(reference.signed_xml)
    




