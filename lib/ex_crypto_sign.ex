defmodule ExCryptoSign do

  alias ExCryptoSign.XmlDocument
  alias ExCryptoSign.Components.{PropertiesObject, SignedInfo, KeyInfo}
  alias ExCryptoSign.Properties.{SignedSignatureProperties, SignedDataObjectProperties, UnsignedSignatureProperties}


  @moduledoc """
  Documentation for `ExCryptoSign`.
  """

  @doc """
  takes in a documents and prepares the xml structure for signing by the client.

  It is generating an external signature. If an embedded signature is needed, use the `prepare_raw_embedded` function.
  """
  def prepare_document(signature_id, documents, x509_pem_certificate, doc_opts) do
    key_info = KeyInfo.new() |> KeyInfo.put_x509_data(x509_pem_certificate)


    s_info = documents
    |> Enum.reduce({1, SignedInfo.new(signature_id)}, fn document, {index, signed_info} ->
      next_info = signed_info |> SignedInfo.add_document_digest("doc-#{index}", "\#data-#{document.id}", :sha3_512, document.content)
      {index + 1, next_info}
    end)
    |> case do
      {_, signed_info} ->
        signed_info
      end
   # |> SignedInfo.put_signature_method(:ecdsa_sha3_512)
    |> SignedInfo.put_signature_method(:ecdsa_sha256)
    |> SignedInfo.put_signed_property_digest(:sha3_512, get_properties_object(doc_opts))



    ExCryptoSign.XmlDocument.new(signature_id, [
      key_info: key_info,
      signed_info: s_info,
      object: get_properties_object(doc_opts)
    ])
    |> ExCryptoSign.XmlDocument.build_xml()


  end

  @doc """
  the documents must have a content. It will be embedded in the xml document. It does not need to be a pdf and the id does not need to be existent.
  """
  def prepare_raw_embedded(signature_id, documents, x509_pem_certificate, doc_opts) do
    key_info = KeyInfo.new() |> KeyInfo.put_x509_data(x509_pem_certificate)


    s_info = documents
    |> Enum.reduce({1, SignedInfo.new(signature_id)}, fn document, {index, signed_info} ->
      next_info = signed_info |> SignedInfo.add_document_digest("doc-#{index}", "#data-content-#{document.id}", :sha3_512, document.content)
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
      object: get_properties_object(doc_opts),
      embedded_documents: documents
    ])
    |> ExCryptoSign.XmlDocument.build_xml()




  end


  @spec sign_and_verify(any, any, any, any, keyword) ::
          {:error, :cert_digest | :cert_validy_date | :doc | :signature | :signed_props}
          | {:ok, binary}
  @doc """
  generates the xml document add the signature and verifies if the signature is actually valid for the given documents

  returns {:ok, signed_xml} if the signature is valid
  returns {:error, error_type} if the signature is invalid

  """
  def sign_and_verify(signature_id, documents, x509_pem_certificate, signature_base64, doc_opts) do
    xml = prepare_document(signature_id, documents, x509_pem_certificate, doc_opts)
      |> ExCryptoSign.Util.Signer.add_signature(signature_base64)

    document_contents = documents |> Enum.map(fn document -> document.content end)

    case ExCryptoSign.Util.Verifier.verifies_document(xml, document_contents) do
      {:ok, true} -> {:ok, xml}
      {:error, error_type} -> {:error, error_type}
    end

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


  defdelegate get_document_ids(xml_string), to:  XmlDocument, as: :parse_document_urls


  def export_document_signatures(xml_string, documents) do
    xml = xml_string |> XmlDocument.parse_document()

    XmlDocument.export(xml, documents)
  end


end
