defmodule ExCryptoSign.Util.Verifier do
alias ExCryptoSign.Constants.SignatureMethods
alias ElixirSense.Providers.Signature
alias ExCryptoSign.Util.Signer
alias ExCryptoSign.Util.PemCertificate

  defp certificate_matches?(xml_document) do
    # get the certificate from the xml document


    cert = xml_document.key_info.x509_data
    digest = cert |> PemCertificate.get_certificate_digest(:sha256)

    # get the certificate digest method

    signing_cert_digest = xml_document.object.signed_signature_properties.signing_certificate.digest


    # compare the digests
    signing_cert_digest == digest

  end

  @doc """
  checks wether the certificate used for signing has been expired during the signing time
  """
  def cert_valid_at_signing?(xml_document) do
    cert = xml_document.key_info.x509_data
    signing_date = xml_document.object.signed_signature_properties.signing_time
    parsed_date = signing_date
    |> DateTime.from_iso8601()
    |> case do
      {:ok, date, _offset_utc} -> date
      {:error, _} -> 0
    end
    PemCertificate.is_cert_valid_at?(cert, parsed_date)
  end

  def signature_valid?(xml_document) do
    signature = xml_document.signature_value
    signed_info = xml_document.signed_info

    # get the signature method
    signature_method = signed_info.signature_method

    # get the signature value
    signature_value = signature.value |> Base.decode64!()

    # compute validation digest
    xml_string = ExCryptoSign.XmlDocument.build_xml(xml_document)
    valdidate_string = Signer.compute_canonicalized_sign_info(xml_string)
    used_digest = SignatureMethods.get_digest_method(signature_method)

    # get public key from included certificate

    cert = xml_document.key_info.x509_data
    public_key = PemCertificate.get_public_key(cert)


    # validate the signature using public key
    :public_key.verify(valdidate_string, used_digest, signature_value, public_key)
  end

  def verifies_document(xml_string, document_contents) do
    xml_document = ExCryptoSign.XmlDocument.parse_document(xml_string)
    signed_info = xml_document.signed_info

    signature_properties = ExCryptoSign.Components.PropertiesObject.parse_document(xml_string)

    signed_properties_xml = signature_properties
    |> ExCryptoSign.Components.PropertiesObject.build_signature_xml()

    # check whether the documents are contained in signed info
    contains_documents = ExCryptoSign.Components.SignedInfo.contains_documents?(signed_info, document_contents)
    # check whether the signed properties are contained in signed info



    contains_signed_property = ExCryptoSign.Components.SignedInfo.contains_signed_property?(signed_info, signed_properties_xml)



    cert_match = certificate_matches?(xml_document)

    cert_valid_at_signing = cert_valid_at_signing?(xml_document)


    with {:doc, true} <- {:doc, contains_documents},
          {:signed_props, true} <- {:signed_props, contains_signed_property},
          {:cert_digest, true} <- {:cert_digest, cert_match},
          {:cert_validy_date, true} <- {:cert_validy_date, cert_valid_at_signing},
          {:signature, true} <- {:signature, signature_valid?(xml_document)}
          do
        {:ok, true}
      else
        {error_type, _} -> {:error, error_type}
      end

  end

end
