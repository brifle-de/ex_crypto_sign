# ExCryptoSign

This libary allows it to generate signatures in xml format.

## Note

This is the signature algorithm which is used by Brifle for generating XaDES signatures. It can only generate and validate those signatures yet.

It uses SHA-256, SHA3-512 and ECDSA with a 256 bit key. No other algorithm are fully supported yet.

TODO: Add larger key length
 

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
        signing_time: "2019-01-01T00:00:00Z",
        signing_certificate: %{
          issuer: "issuer",
          serial: "serial",
          digest_type: :sha256,
          digest: :crypto.hash(:sha256, "digest") |> Base.encode64()
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
    ExCryptoSign.write_to_file!(doc, export)


```

