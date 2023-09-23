defmodule ExCryptoSign do

  alias ExCryptoSign.Components.{PropertiesObject, SignedInfo, KeyInfo}
  alias ExCryptoSign.Properties.{SignedSignatureProperties, SignedDataObjectProperties, UnsignedSignatureProperties}


  @moduledoc """
  Documentation for `ExCryptoSign`.
  """

  @doc """
  takes in a documents and prepares the xml structure for signing by the client
  """
  def prepare_document(signature_id, documents, x509_dem_certificate, doc_opts) do
    key_info = KeyInfo.new() |> KeyInfo.put_x509_data(x509_dem_certificate)




    s_info = documents
    |> Enum.reduce({1, SignedInfo.new(signature_id)}, fn document, {index, signed_info} ->
      next_info = signed_info |> SignedInfo.add_document_digest("doc-#{index}", "https://documents.brifle.de/#{document.id}", :sha3_512, document.content)
      {index + 1, next_info}
    end)
    |> case do
      {_, signed_info} ->
        signed_info
      end
    |> SignedInfo.put_signature_method(:ecdsa_sha3_512)
    |> SignedInfo.put_signed_property_digest(:sha3_512, get_properties_object(doc_opts))

    ExCryptoSign.XmlDocument.new(signature_id, [
      key_info: key_info,
      signed_info: s_info,
      object: get_properties_object(doc_opts)
    ])
    |> ExCryptoSign.XmlDocument.build_xml()



  end


  defp get_properties_object(docs_opts) do

    opts_signature_properties = Keyword.get(docs_opts, :signature_properties, %{})
    opts_signed_data_object_properties = Keyword.get(docs_opts, :signed_data_object_properties, %{})
    opts_unsigned_signature_properties = Keyword.get(docs_opts, :unsigned_signature_properties, %{})

    signature_properties = SignedSignatureProperties.new(opts_signature_properties)

    signed_data_object_properties = SignedDataObjectProperties.new(opts_signed_data_object_properties)

    unsigned_signature_properties = UnsignedSignatureProperties.new(opts_unsigned_signature_properties)


    PropertiesObject.new()
    |> PropertiesObject.put_signed_properties(signature_properties)
    |> PropertiesObject.put_signed_data_object_properties(signed_data_object_properties)
    |> PropertiesObject.put_unsigned_signature_properties(unsigned_signature_properties)

  end

  def test_signature() do

    {_pem_key, pem_cert} = generate_dummy_cert()

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

    prepare_document("signature_id",[%{content: "document1", id: "2341ac23HAbcA"}, %{content: "document2", id: "671ac23HAbcA"}], pem_cert, docs_opts)

  end

  def generate_dummy_cert() do
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

    {pem_key, pem_cert}
  end

  def parse_key(key) do
    {:ok, key} = X509.PrivateKey.from_pem(key)
    key
  end




end
