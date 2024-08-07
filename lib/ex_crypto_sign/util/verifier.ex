defmodule ExCryptoSign.Util.Verifier do
alias ExCryptoSign.Constants.SignatureMethods
alias ElixirSense.Providers.Signature
alias ExCryptoSign.Util.Signer
alias ExCryptoSign.Util.PemCertificate

  def certificate_matches?(xml_document) do
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


  def validate_root_cert(_xml_document, []), do: true
  def validate_root_cert(xml_document, allowed_root_certificates) do
    cert = xml_document.key_info.x509_data
    root_cert = PemCertificate.get_expanded_pem(cert)
    Enum.any?(allowed_root_certificates, fn cert ->
      case PemCertificate.validate_certificate_chain(root_cert, cert) do
        {:ok, _} -> true
        {:error, _} -> false
      end
    end)
  end

   @doc """
  computes the length of the key in bytes
  """
  defp compute_ecc_key_length(private_key) do
    curve_name = PrivateKey.fromPem!(private_key).curve.name
    cond do
      curve_name.contains?("256") -> 32
      curve_name.contains?("384") -> 48
      curve_name.contains?("521") -> 66
      true -> 32
    end
  end

  def signature_valid?(xml_document) do
    signature = xml_document.signature_value
    signed_info = xml_document.signed_info

    # get the signature method
    signature_method = signed_info.signature_method

    # get public key curve
    {{:ECPoint, pk}, _} = xml_document.key_info.x509_data |> PemCertificate.get_public_key()

    # comput the bytes size of the public key
    # division by two can be skipped based on the following hex encoding
    signature_component_size = (byte_size(pk) - 1)

    # get the signature value
    raw_signature = signature.value |> Base.decode64!() |> Base.encode16()
    r = raw_signature |> String.slice(0, signature_component_size) |> String.to_integer(16)
    s = raw_signature |> String.slice(signature_component_size, signature_component_size) |> String.to_integer(16)

    signature_value = %EllipticCurve.Signature{
      r: r,
      s: s
    }
      |> EllipticCurve.Signature.toBase64()
      |> Base.decode64!()

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

  @doc """
  verifies the signature of an exported xml document
  """
  def verify_exported_signature(xml_string, opts \\ []) do
    xml_document = ExCryptoSign.XmlDocument.parse_document(xml_string)
    # get the embedded documents
    documents = xml_document.embedded_documents
    ExCryptoSign.Util.Verifier.verifies_document(xml_string, documents, opts)
  end


  def verifies_document(xml_string, documents, opts \\ []) do
    xml_document = ExCryptoSign.XmlDocument.parse_document(xml_string)

    allowed_root_certificates = Keyword.get(opts, :allowed_root_certificates, [])

    signed_info = xml_document.signed_info

    signature_properties = ExCryptoSign.Components.PropertiesObject.parse_document(xml_string)

    signed_properties_xml = signature_properties
    |> ExCryptoSign.Components.PropertiesObject.build_signature_xml()

    # check whether the documents are contained in signed info
    contains_documents = ExCryptoSign.Components.SignedInfo.contains_documents?(signed_info, documents)
    # check whether the signed properties are contained in signed info

    contains_signed_property = ExCryptoSign.Components.SignedInfo.contains_signed_property?(signed_info, signed_properties_xml)

    cert_match = certificate_matches?(xml_document)

    cert_valid_at_signing = cert_valid_at_signing?(xml_document)

    with {:doc, true} <- {:doc, contains_documents},
          {:signed_props, true} <- {:signed_props, contains_signed_property},
          {:cert_digest, true} <- {:cert_digest, cert_match},
          {:cert_validy_date, true} <- {:cert_validy_date, cert_valid_at_signing},
          {:signature, true} <- {:signature, signature_valid?(xml_document)},
          {:root_cert, true} <- {:root_cert, validate_root_cert(xml_document, allowed_root_certificates)}
          do
        {:ok, true}
      else
        {error_type, _} -> {:error, error_type}
      end

  end

end
