# ExCryptoSign

This libary allows it to generate signatures in xml format.

## Note

This is the signature algorithm which is used by Brifle for generating XaDES signatures. It can only generate and validate those signatures yet.

It uses SHA-256, SHA3-512 and ECDSA with a 256 bit key. No other algorithm are fully supported yet.

TODO: Add larger key length
TODO: Add Docker File for setup of a validation server
 

## Example

```elixir

# generate test cert and key 

    ca_key = X509.PrivateKey.new_ec(:secp256r1)
    ca = X509.Certificate.self_signed(ca_key,"/C=US/ST=CA/L=San Francisco/O=Acme/CN=ECDSA Root CA", template: :root_ca)

    my_key = X509.PrivateKey.new_ec(:secp256r1)
    my_cert = my_key |>

    X509.PublicKey.derive()
    |> X509.Certificate.new(
      "/C=US/ST=CA/L=San Francisco/O=Acme/CN=Sample",
      ca, ca_key,
      extensions: [
        subject_alt_name: X509.Certificate.Extension.subject_alt_name(["example.org", "www.example.org"])
      ]
    )

    pem_key = X509.PrivateKey.to_pem(my_key)
    pem_cert = X509.Certificate.to_pem(my_cert)

    # dummy data 

    docs_opts = [
      signature_properties: %{
        signing_time: DateTime.now!("Etc/UTC") |> DateTime.to_iso8601(),
        signing_certificate: %{
          issuer: ExCryptoSign.Util.PemCertificate.get_certificate_issuer(pem_cert),
          serial: ExCryptoSign.Util.PemCertificate.get_certificate_serial(pem_cert),
          digest_type: :sha256,
          digest: ExCryptoSign.Util.PemCertificate.get_certificate_digest(pem_cert, :sha256)
        },
        signature_production_place: %{
          city_name: "Stuttgart",
          country: "Germany"
        },
        signer_role: %{
          claimed_roles: ["role1", "role2"]
        }
      },
      signed_data_object_properties: %{
        data_object_format: %{
          mime_type: "text/xml",
          encoding: "UTF-8",
          description: "Die Beschreibung",
        }
      },
      unsigned_signature_properties: %{

      }
    ]

    # prepare document for signing

    signature_document = ExCryptoSign.prepare_document("signature_id",[%{content: "document1", id: "2341ac23HAbcA"}, %{content: "document2", id: "671ac23HAbcA"}], pem_cert, docs_opts)

    # sign the document

    {:ok, {doc, sign}} = ExCryptoSign.Util.Signer.sign(signature_document, pem_key)

    # it must match with the configured base_url, default: "https://documents.brifle.de/"
    export_data = %{"https://documents.brifle.de/2341ac23HAbcA" => "document1", "https://documents.brifle.de/671ac23HAbcA" => "document2"}

    export = ExCryptoSign.export_document_signatures(doc, export_data)

    # store the signature document
    export_path = "./export-signature.xml"
    
    File.write!(export_path, export)

```


This example produces the following signature

```xml
<SignatureDocument xmlns="http://uri.etsi.org/01903/v1.1.1#" elementFormDefault="qualified" targetNamespace="http://uri.etsi.org/01903/v1.1.1#">
  <Metadata>
    <baseUrl>https://documents.brifle.de/</baseUrl>
    <version>1.0</version>
  </Metadata>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="signature_id">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"></ds:SignatureMethod>
      <ds:Reference Id="doc-1" URI="#data-2341ac23HAbcA">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2007/05/xmldsig-more#sha3-512"></ds:DigestMethod>
        <ds:DigestValue>
          Lm1XgFBVWK+dRSVTb+YYWc8XvqTemGRJiEpXI51CGFVw32M3KNwMrf9R2wD1H2cXuLzRcGyTGUVZxnAF/QridA==
        </ds:DigestValue>
      </ds:Reference>
      <ds:Reference Id="doc-2" URI="#data-671ac23HAbcA">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2007/05/xmldsig-more#sha3-512"></ds:DigestMethod>
        <ds:DigestValue>
          GCIJ8ibIDW4azJbsSTM9/RpLkETt4Da7U+CI3coz5iUOJ5S6/oM5UTsKrYIRQhCA/fN0ZZSc3tGOSHde3QhGcg==
        </ds:DigestValue>
      </ds:Reference>
      <ds:Reference URI="#SignedProperties">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2007/05/xmldsig-more#sha3-512"></ds:DigestMethod>
        <ds:DigestValue>
          /oEwoeboq2FTY2fnUffDole2VCiFA3p1j6evJS8oFh6AR2rLb26V96jDb5hxu5rx+0mSPR3zzjMpXIjWy52Jrg==
        </ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>
      Yrjmagdsmk0ODweGbwrpBF2nrqV4EW1qmvFdBM6UnoLVUZlg+zqpx3wtkHrfJwWgStG6D6/DozyIlesLCtCH1w==
    </ds:SignatureValue>
    <ds:KeyInfo>
      <ds:X509Data>
        <ds:X509Certificate>
          MIICSDCCAe6gAwIBAgIIGtWW0h9GdQUwCgYIKoZIzj0EAwIwWTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMQ0wCwYDVQQKDARBY21lMRYwFAYDVQQDDA1FQ0RTQSBSb290IENBMB4XDTI0MDUyNTE5MTkzNVoXDTI1MDYyNDE5MjQzNVowUjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMQ0wCwYDVQQKDARBY21lMQ8wDQYDVQQDDAZTYW1wbGUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQsdFN2703z7ZEMAzSBPwcmfiVCZV0sMfTJyery2UF+NlWgUmv5Zyk3vHvzjvSbtouXj5bbS9yrW+Mmc4zCuJNdo4GmMIGjMAkGA1UdEwQCMAAwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNVHQ4EFgQUMbtZPD8l00SbyJWLj/4Rb5ouKTAwHwYDVR0jBBgwFoAUs2vrryeDEDqz0amAreXc10EFm9cwJwYDVR0RBCAwHoILZXhhbXBsZS5vcmeCD3d3dy5leGFtcGxlLm9yZzAKBggqhkjOPQQDAgNIADBFAiAYcNUut5K70/fM6iZmrAB4nrH9BrtKgRwSdF13ohUS6AIhAJ2pGaOfmxEHrZfq9puIBigF+QzDaQ9a8q/PD4fNGCir
        </ds:X509Certificate>
      </ds:X509Data>
    </ds:KeyInfo>
    <ds:Object>
      <xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Target="#signature_id">
        <xades:SignedProperties Id="SignedProperties">
          <xades:SignedSignatureProperties>
            <xades:SigningTime>
              2024-05-25T19:45:56.571073Z
            </xades:SigningTime>
            <xades:SigningCertificate>
              <xades:Cert>
                <xades:CertDigest>
                  <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>
                  <ds:DigestValue>
                    jNgN3T4rKYQc8FBuZvY8NPwEwQbOO7FpsnnYPQQfO1w=
                  </ds:DigestValue>
                </xades:CertDigest>
                <xades:IssuerSerial>
                  <ds:X509IssuerName>
                    ECDSA Root CA
                  </ds:X509IssuerName>
                  <ds:X509SerialNumber>
                    1933617444237505797
                  </ds:X509SerialNumber>
                </xades:IssuerSerial>
              </xades:Cert>
            </xades:SigningCertificate>
            <xades:SignaturePolicyIdentifier>
              <xades:SignaturePolicyImplied></xades:SignaturePolicyImplied>
            </xades:SignaturePolicyIdentifier>
            <xades:SignatureProductionPlace>
              <xades:City>
                Stuttgart
              </xades:City>
              <xades:CountryName>
                Germany
              </xades:CountryName>
            </xades:SignatureProductionPlace>
            <xades:SignerRole>
              <xades:ClaimedRoles>
                <xades:ClaimedRole>
                  role1
                </xades:ClaimedRole>
                <xades:ClaimedRole>
                  role2
                </xades:ClaimedRole>
              </xades:ClaimedRoles>
              <xades:CertifiedRoles>

              </xades:CertifiedRoles>
            </xades:SignerRole>
          </xades:SignedSignatureProperties>
          <xades:SignedDataObjectProperties>
            <xades:DataObjectFormat ObjectReference="">
              <xades:MimeType>
                text/xml
              </xades:MimeType>
              <xades:Encoding>
                UTF-8
              </xades:Encoding>
              <xades:ObjectIdentifier>
                <xades:Description>
                  Die Beschreibung
                </xades:Description>
              </xades:ObjectIdentifier>
            </xades:DataObjectFormat>
          </xades:SignedDataObjectProperties>
        </xades:SignedProperties>
        <xades:UnsignedProperties>
          <xades:UnsignedSignatureProperties></xades:UnsignedSignatureProperties>
        </xades:UnsignedProperties>
      </xades:QualifyingProperties>
    </ds:Object>
  </ds:Signature>
  <ContentExport>
    <SignatureContent id="data-2341ac23HAbcA">document1</SignatureContent>
    <SignatureContent id="data-671ac23HAbcA">document2</SignatureContent>
  </ContentExport>
</SignatureDocument>
```
To validate this signature you can run

```elixir
export_path = "./export-signature.xml"
xml_string = File.read!(export_path)

{:ok, true} = ExCryptoSign.Util.Verifier.verify_exported_signature(xml_string)

```