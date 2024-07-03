defmodule VerifierTest do
  alias ExCryptoSign.XmlDocument
  use ExUnit.Case



  test "verifies successul" do
    #{key_pem, cert_pem} = Support.CertCreator.generate_dummy_cert(:secp384r1)
    {key_pem, cert_pem} = Support.CertCreator.generate_dummy_cert(:secp256r1)
    key = Support.CertCreator.private_key_from_pem(key_pem)
    signature_xml_string = create_signature(cert_pem, key_pem)
    res = ExCryptoSign.Util.Verifier.verifies_document(signature_xml_string, [%{content: "document1", id: "2341ac23HAbcA"}, %{content: "document2", id: "671ac23HAbcA"}])

    assert {:ok, true} = res
  end

  test "verifies successul larger key" do
    {key_pem, cert_pem} = Support.CertCreator.generate_dummy_cert(:secp384r1)
    key = Support.CertCreator.private_key_from_pem(key_pem)
    signature_xml_string = create_signature(cert_pem, key_pem)
    res = ExCryptoSign.Util.Verifier.verifies_document(signature_xml_string, [%{content: "document1", id: "2341ac23HAbcA"}, %{content: "document2", id: "671ac23HAbcA"}])

    assert {:ok, true} = res


    {key_pem, cert_pem} = Support.CertCreator.generate_dummy_cert(:secp521r1)
    key = Support.CertCreator.private_key_from_pem(key_pem)
    signature_xml_string = create_signature(cert_pem, key_pem)
    res = ExCryptoSign.Util.Verifier.verifies_document(signature_xml_string, [%{content: "document1", id: "2341ac23HAbcA"}, %{content: "document2", id: "671ac23HAbcA"}])

    assert {:ok, true} = res
  end

  test "verifies invalid root ca" do

    {key, cert} = Support.CertCreator.generate_ca()
    cert_pem = cert |> X509.Certificate.to_pem()
    root_certs = [cert_pem]


    xml = File.read!("test/files/exported_valid_signature.xml")
    assert {:error, :root_cert} = ExCryptoSign.Util.Verifier.verify_exported_signature(xml, allowed_root_certificates: root_certs)
  end

  test "verifies exported successul" do
    xml = File.read!("test/files/exported_valid_signature.xml")
    assert {:ok, true} = ExCryptoSign.Util.Verifier.verify_exported_signature(xml)
  end

  test "invalid signature exported successul" do
    xml = File.read!("test/files/exported_invalid_signature.xml")
    assert {:error, :signature} = ExCryptoSign.Util.Verifier.verify_exported_signature(xml)
  end

  test "invalid digest exported successul" do
    xml = File.read!("test/files/exported_invalid_digest_signature.xml")
    assert {:error, :doc} = ExCryptoSign.Util.Verifier.verify_exported_signature(xml)
  end

  test "error wrong documents" do
    {key_pem, cert_pem} = Support.CertCreator.generate_dummy_cert()
    _key = Support.CertCreator.private_key_from_pem(key_pem)
    signature_xml_string = create_signature(cert_pem, key_pem)
    res = ExCryptoSign.Util.Verifier.verifies_document(signature_xml_string, [%{content: "document3", id: "2341ac23HAbcA"}, %{content: "document5", id: "671ac23HAbcA"}])

    assert {:error, :doc} = res
  end

  test "error certifcate invalid at signing time" do
    {key_pem, cert_pem} = Support.CertCreator.generate_dummy_cert()
    _key = Support.CertCreator.private_key_from_pem(key_pem)
    signature_xml_string = create_signature_old(cert_pem, key_pem)
    res = ExCryptoSign.Util.Verifier.verifies_document(signature_xml_string, [%{content: "document1", id: "2341ac23HAbcA"}, %{content: "document2", id: "671ac23HAbcA"}])

    assert {:error, :cert_validy_date} = res

  end

  test "error certifcate invalid" do
    {key_pem, cert_pem} = Support.CertCreator.generate_dummy_cert()
    _key = Support.CertCreator.private_key_from_pem(key_pem)
    signature_xml_string = create_signature_wrong_cert(cert_pem, key_pem)
    res = ExCryptoSign.Util.Verifier.verifies_document(signature_xml_string, [%{content: "document1", id: "2341ac23HAbcA"}, %{content: "document2", id: "671ac23HAbcA"}])

    assert {:error, :cert_digest} = res

  end

  test "error properties wrong" do
    {key_pem, cert_pem} = Support.CertCreator.generate_dummy_cert()
    key = Support.CertCreator.private_key_from_pem(key_pem)
    signature_xml_string = create_signature(cert_pem, key_pem)

    doc = XmlDocument.parse_document(signature_xml_string)

    obj = doc.object

    signed_props = obj.signed_signature_properties

    # manipulate the city

    signed_props = signed_props |> Map.put(:signature_production_place, %{city_name: "Berlin", country: "Germany"})

    obj = obj |> Map.put(:signed_signature_properties, signed_props)

    doc = doc |> Map.put(:object, obj)

    signature_xml_string_manipulated = XmlDocument.build_xml(doc)

    res = ExCryptoSign.Util.Verifier.verifies_document(signature_xml_string_manipulated, [%{content: "document1", id: "2341ac23HAbcA"}, %{content: "document2", id: "671ac23HAbcA"}])

    assert {:error, :signed_props} = res

  end

  test "wrong signature" do
    {key_pem, cert_pem} = Support.CertCreator.generate_dummy_cert()
    key = Support.CertCreator.private_key_from_pem(key_pem)
    signature_xml_string = create_signature_wrong_key(cert_pem, key_pem)
    res = ExCryptoSign.Util.Verifier.verifies_document(signature_xml_string, [%{content: "document1", id: "2341ac23HAbcA"}, %{content: "document2", id: "671ac23HAbcA"}])

    assert {:error, :signature} = res
  end

  defp create_signature_wrong_cert(pem_cert, pem_key) do

    {key_pem, cert_pem} = Support.CertCreator.generate_dummy_cert()

    docs_opts = [
      signature_properties: %{
        signing_time: DateTime.now!("Etc/UTC") |> DateTime.add(3600, :second) |> DateTime.to_string,
        signing_certificate: %{
          issuer: ExCryptoSign.Util.PemCertificate.get_certificate_issuer(cert_pem),
          serial: ExCryptoSign.Util.PemCertificate.get_certificate_serial(cert_pem),
          digest_type: :sha256,
          digest: ExCryptoSign.Util.PemCertificate.get_certificate_digest(cert_pem, :sha256)
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
          object_reference: "document1",
          object_identifier: "https://docs.brifle.de/2341ac23HAbcA"
        }
      },
      unsigned_signature_properties: %{

      }
    ]

    # prepare document for signing

    signature_document = ExCryptoSign.prepare_document("signature_id",[%{content: "document1", id: "2341ac23HAbcA"}, %{content: "document2", id: "671ac23HAbcA"}], pem_cert, docs_opts)
    {:ok, {doc, sign}} = ExCryptoSign.Util.Signer.sign(signature_document, pem_key)
    doc
  end


  defp create_signature(pem_cert, pem_key) do

    docs_opts = [
      signature_properties: %{
        signing_time: DateTime.now!("Etc/UTC") |> DateTime.add(3600, :second) |> DateTime.to_string,
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

      }
    ]

    # prepare document for signing

    signature_document = ExCryptoSign.prepare_document("signature_id",[%{content: "document1", id: "2341ac23HAbcA"}, %{content: "document2", id: "671ac23HAbcA"}], pem_cert, docs_opts)
    {:ok, {doc, sign}} = ExCryptoSign.Util.Signer.sign(signature_document, pem_key)
    doc
  end

  defp create_signature_wrong_key(pem_cert, pem_key) do

    {key_pem, cert_pem} = Support.CertCreator.generate_dummy_cert()

    docs_opts = [
      signature_properties: %{
        signing_time: DateTime.now!("Etc/UTC") |> DateTime.add(3600, :second) |> DateTime.to_string,
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
          object_reference: "document1",
          object_identifier: "https://docs.brifle.de/2341ac23HAbcA"
        }
      },
      unsigned_signature_properties: %{

      }
    ]

    # prepare document for signing

    signature_document = ExCryptoSign.prepare_document("signature_id",[%{content: "document1", id: "2341ac23HAbcA"}, %{content: "document2", id: "671ac23HAbcA"}], pem_cert, docs_opts)
    {:ok, {doc, sign}} = ExCryptoSign.Util.Signer.sign(signature_document, key_pem)
    doc
  end



  defp create_signature_old(pem_cert, pem_key) do

    docs_opts = [
      signature_properties: %{
        signing_time: "2019-01-01T00:00:00Z",
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
          object_reference: "document1",
          object_identifier: "https://docs.brifle.de/2341ac23HAbcA"
        }
      },
      unsigned_signature_properties: %{

      }
    ]

    # prepare document for signing

    signature_document = ExCryptoSign.prepare_document("signature_id",[%{content: "document1", id: "2341ac23HAbcA"}, %{content: "document2", id: "671ac23HAbcA"}], pem_cert, docs_opts)
    {:ok, {doc, sign}} = ExCryptoSign.Util.Signer.sign(signature_document, pem_key)
    doc
  end


end
