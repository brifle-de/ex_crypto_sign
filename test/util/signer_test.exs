defmodule ExCryptoSign.Util.SignerTest do
  alias ExCryptoSign.Util.Signer

  use ExUnit.Case


   test "sign_rsa/2" do
    {pem_key, pem_cert} = Support.CertCreator.generate_dummy_cert(:rsa2048)


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

    #signature_document = ExCryptoSign.prepare_document("signature_id",[%{content: "document1", id: "2341ac23HAbcA"}, %{content: "document2", id: "671ac23HAbcA"}], pem_cert, docs_opts)
   # {:ok, {doc, sign}} = ExCryptoSign.Util.Signer.sign(signature_document, pem_key)
    #doc

  end

  test "sign/2" do
    {pem_key, pem_cert} = Support.CertCreator.generate_dummy_cert(:secp256r1)


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

end
