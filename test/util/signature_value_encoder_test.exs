defmodule ExCryptoSign.Util.SignatureValueEncoderTest do

  use ExUnit.Case
  alias ExCryptoSign.Util.SignatureValueEncoder

  test "create test files" do
    {doc, sign, export} = create_signature_value()


    File.write!("test/files/v1_1/rsa/signature_1.xml", doc)
    File.write!("test/files/v1_1/rsa/signature_1_exported.xml", export)
  end


  defp create_signature_value() do
    {pem_key, pem_cert} = Support.CertCreator.generate_dummy_cert(:rsa2048)


    docs_opts = [
      signature_properties: %{
        signing_time: DateTime.now!("Etc/UTC") |> DateTime.add(3600, :second) |> DateTime.to_iso8601(),
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
        data_object_format: [
          %{
          mime_type: "text/xml",
          encoding: "UTF-8",
          description: "Die Beschreibung",
          object_reference: "document1",
          object_identifier: "https://docs.brifle.de/2341ac23HAbcA"
        },
        %{
          mime_type: "text/xml",
          encoding: "UTF-8",
          description: "Die Beschreibung",
          object_reference: "document2",
          object_identifier: "https://docs.brifle.de/671ac23HAbcA"
        }
      ]
      },
      unsigned_signature_properties: %{

      },
      signature_algorithm: :rsa_sha256
    ]

    # prepare document for signing

    signature_document = ExCryptoSign.prepare_document("signature_id",[%{content: "document1", id: "2341ac23HAbcA"}, %{content: "document2", id: "671ac23HAbcA"}], pem_cert, docs_opts)
    {:ok, {doc, sign}} = ExCryptoSign.Util.Signer.sign(signature_document, pem_key)

    export = ExCryptoSign.export_document_signatures(doc, %{"https://docs.brifle.de/2341ac23HAbcA" => "document1", "https://docs.brifle.de/671ac23HAbcA" => "document2"})

    {doc, sign, export}
  end

  test "parse raw signature (secp256r1)" do

    values = [
      {
        "W8qYLQvfir6bZ7MIbXEAM8BhL+Pk5jVzZMakJBcO20uNiZUoM/W3Y1iiHDlqPOhqCffvFoU1uTe/PK5ZuCadXQ==",
        "MEUCIFvKmC0L34q+m2ezCG1xADPAYS/j5OY1c2TGpCQXDttLAiEAjYmVKDP1t2NYohw5ajzoagn37xaFNbk3vzyuWbgmnV0="
      },
      {
        "ITB5U8KazvToBRdZ5PcY8PHRrP1yYYzXy+wQ8MZNP+Y2umbVcgkJRf5NBpv/8DkXWcb81vHE/W45ZLlkFTDWjQ==",
        "MEQCICEweVPCms706AUXWeT3GPDx0az9cmGM18vsEPDGTT/mAiA2umbVcgkJRf5NBpv/8DkXWcb81vHE/W45ZLlkFTDWjQ=="
      },
      {
        "TplFegd06sHx203GeQC49hGdBbo1rySup+2cZHwRW46N79OU/vl7rkXbALlt7syxMjNCdNh1wgdbhnp8D1lzng==",
        "MEUCIE6ZRXoHdOrB8dtNxnkAuPYRnQW6Na8krqftnGR8EVuOAiEAje/TlP75e65F2wC5be7MsTIzQnTYdcIHW4Z6fA9Zc54="
      },
      {
        "qfnUPDCR2rvFUw9X5KovtqmNEqHeHXYAbRZsMPfK6b6glYgIAUGHTQkCU8qSYDH729WrBLTfQguff0ak0RzdNg==",
        "MEYCIQCp+dQ8MJHau8VTD1fkqi+2qY0Sod4ddgBtFmww98rpvgIhAKCViAgBQYdNCQJTypJgMfvb1asEtN9CC59/RqTRHN02"
      },
      {
        "02UX2n+s2NKR5aZtTgzeXj/DMX9hzvfmt63rzGJ7KialuVoWvvY2fD/ofozsG3inCfKcn4E/vHenZTGQGURPeTr5PWCDNXk5c2FE38N9gUF4u569p5UdHn+8UGx+0eyf",
        "MGUCMQDTZRfaf6zY0pHlpm1ODN5eP8Mxf2HO9+a3revMYnsqJqW5Wha+9jZ8P+h+jOwbeKcCMAnynJ+BP7x3p2UxkBlET3k6+T1ggzV5OXNhRN/DfYFBeLuevaeVHR5/vFBsftHsnw=="
      }
    ]

    Enum.each(values, fn {raw_sig, der_sig} ->
      signature = SignatureValueEncoder.parse_signature_value!(:ecdsa, raw_sig)

      expected = der_sig

      actual = EllipticCurve.Signature.toBase64(%EllipticCurve.Signature{r: signature.ecdsa.r, s: signature.ecdsa.s})
      computed = SignatureValueEncoder.to_base64(signature)

      assert actual == expected && computed == expected
    end)



  end

  test "parse der signature (secp256r1)" do

    # Generate private key for testing
    # {pem_key, pem_cert} = Support.CertCreator.generate_dummy_cert(:secp256r1)

    privateKey = EllipticCurve.PrivateKey.generate()

    signature_value = EllipticCurve.Ecdsa.sign("my message", privateKey) |> EllipticCurve.Signature.toBase64()


    signature = SignatureValueEncoder.parse_signature_value!(:ecdsa, signature_value)



  end



end
