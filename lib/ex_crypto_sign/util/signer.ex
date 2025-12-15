defmodule ExCryptoSign.Util.Signer do
  alias ExCryptoSign.Util.SignatureValueEncoder
  alias ExCryptoSign.Constants.{CanonicalizationMethods, SignatureMethods}

  alias ExCryptoSign.Util.PemCertificate
  def sign(xml_string, private_key) when is_binary(xml_string) do

    # parse the xml document
    xml_document = ExCryptoSign.XmlDocument.parse_document(xml_string)

    xml = SweetXml.parse(xml_string, namespace_conformant: true, document: true)

    signature_method = get_signature_method(xml)

    key_length = get_key_length_bytes(xml_document)

      # compute the signature value
    signature = compute_signature_value(xml_string, private_key)


    IO.inspect(key_length, label: "Key length bytes")
    IO.inspect(signature_method, label: "Signature method")
    signature_value = prepare_signature_value!(signature_method, signature, key_length)


    # put the signature value in the xml document
    xml_document = ExCryptoSign.XmlDocument.put_signature_value(xml_document, signature_value)

    # build the xml document
    xml_document_string = ExCryptoSign.XmlDocument.build_xml(xml_document)

    {:ok, {xml_document_string, signature}}
  end


  @doc """
  adds the signature to the xml document
  """
  def add_signature(xml_string, signature) do

    xml_document = ExCryptoSign.XmlDocument.parse_document(xml_string)

    signature_method = get_signature_method(xml_document)
    key_length = get_key_length_bytes(xml_document)
    signature_value = prepare_signature_value!(signature_method, signature, key_length)

    xml_document = ExCryptoSign.XmlDocument.put_signature_value(xml_document, signature_value)
    ExCryptoSign.XmlDocument.build_xml(xml_document)
  end

  defp prepare_signature_value!(signature_method, signature, key_length) do

    signature_method
      |> SignatureMethods.get_signature_method()
      |> SignatureValueEncoder.parse_signature_value!(signature)
      |> SignatureValueEncoder.to_raw_signature(key_length)
  end

  def get_key_length_bytes(xml_object) do
    public_key = xml_object.key_info.x509_data |> PemCertificate.get_public_key()

    case public_key do
      {{:ECPoint, pk}, _} ->
        # division by two can be skipped based on the following hex encoding
        byte_size(pk) - 1
      {{:RSAPublicKey, n, _e}, _} ->
        byte_size(:public_key.der_encode(:RSAPublicKey, {:RSAPublicKey, n, :undefined}))
      _ ->
        0
    end
  end


  defp get_signature_info(xml_object) do
    SweetXml.xpath(xml_object, SweetXml.sigil_x("//ds:Signature/ds:SignedInfo"))
  end

  def get_canonicalized_method(xml_object) do
    xml_object
    |> SweetXml.xpath(SweetXml.sigil_x("//ds:Signature/ds:SignedInfo/ds:CanonicalizationMethod/@Algorithm"))
    |> to_string()
    |> CanonicalizationMethods.from_w3_url()
  end

  def get_signature_method(xml_object) do
    xml_object
    |> SweetXml.xpath(SweetXml.sigil_x("//ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm"))
    |> to_string()
    |> IO.inspect(label: "Signature Method URL")
    |> SignatureMethods.from_w3_url()
  end

  def compute_canonicalized_sign_info(xml_string) when is_binary(xml_string) do
    xml = SweetXml.parse(xml_string, namespace_conformant: true, document: true)
    compute_canonicalized_sign_info(xml)
  end
  def compute_canonicalized_sign_info(xml) do
    # get the signed info with xpath
    signed_info = get_signature_info(xml)

    # get cananonicalized from signed info
    canonicalized_method = get_canonicalized_method(xml)

    # canonicalize the signed info
    canon = canonicalize(signed_info, canonicalized_method)

    # canon contains the default namespace, this causes frontend problems
    # remove the default namespace by applying a regex on the signedinfo node
    # python canon is removing it as well
    String.replace(canon, ~r/ xmlns=\"([^\"]*)\"/, "")
  end

  def compute_signature_value(xml_string, private_key) do

    xml = SweetXml.parse(xml_string, namespace_conformant: true, document: true)

    # get signature method from signed info
    signature_method = get_signature_method(xml)

    # canonicalize the signed info
    can_info = compute_canonicalized_sign_info(xml)

    # compute the signature value
    signature = compute_sign(can_info, signature_method, private_key)

    # compute signature base 64
    base64_signature = Base.encode64(signature)

    base64_signature
  end

  defp compute_sign(canonicalized_string, signature_method, private_key) when is_binary(private_key) do
    case X509.PrivateKey.from_pem(private_key) do
      {:ok, key} -> compute_sign(canonicalized_string, signature_method, key)
      {:error, _} -> ""
    end
  end

  defp compute_sign(canonicalized_string, signature_method, private_key) do

    digest_method = SignatureMethods.get_digest_method(signature_method)

    :public_key.sign(canonicalized_string, digest_method, private_key)
  end

  def compute_sign_hash(canonicalized_string, signature_method) do
    digest_method = SignatureMethods.get_digest_method(signature_method)

    :crypto.hash(digest_method, canonicalized_string)
  end

  def canonicalize(xml, :exclusive), do: xml |> XmerlC14n.canonicalize!()
  def canonicalize(_xml, _), do: ""

end
