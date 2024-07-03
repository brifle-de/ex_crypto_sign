defmodule ExCryptoSign.Util.Signer do
  alias X509.PublicKey
  alias EllipticCurve.PrivateKey
  alias ExCryptoSign.Constants.{CanonicalizationMethods, SignatureMethods}
  def sign(xml_string, private_key) when is_binary(xml_string) do

    # parse the xml document
    xml_document = ExCryptoSign.XmlDocument.parse_document(xml_string)

      # compute the signature value
    signature = compute_signature_value(xml_string, private_key)

   # convert the signature to raw (r, s) values
    raw_signature = to_raw_signature(signature, compute_ecc_key_length(private_key))

    # put the signature value in the xml document
    xml_document = ExCryptoSign.XmlDocument.put_signature_value(xml_document, raw_signature)

    # build the xml document
    xml_document_string = ExCryptoSign.XmlDocument.build_xml(xml_document)

    {:ok, {xml_document_string, signature}}
  end

  @doc """
  computes the length of the key in bytes
  """
  defp compute_ecc_key_length(private_key) do
    :public_key.pem_decode(private_key)
    |> hd()
    |> :public_key.pem_entry_decode()
    |> then(fn {:ECPrivateKey, 1, key, _, _, _} -> key end)
    |> byte_size()
  end

  def to_raw_signature(base64_signature, curve_size_bytes \\ 32) do

    %EllipticCurve.Signature{
      r: r,
      s: s
    }  = EllipticCurve.Signature.fromBase64!(base64_signature)

    # convert r number to a byte list using big endian and unsigned

    r_bytes = integer_to_bytes(r, curve_size_bytes)
    s_bytes = integer_to_bytes(s, curve_size_bytes)
    signature_bytes = <<r_bytes::binary, s_bytes::binary>>


    base64_string = signature_bytes |> Base.encode64()

    base64_string
  end

  defp integer_to_bytes(integer, byte_length) do
    :binary.encode_unsigned(integer)
    |> pad_left(byte_length)
  end

  defp pad_left(binary, byte_length) do
    padding_length = byte_length - byte_size(binary)
    padding = :binary.copy(<<0>>, padding_length)
    <<padding::binary, binary::binary>>
  end



  @doc """
  adds the signature to the xml document
  """
  def add_signature(xml_string, signature) do
    signature_value = case Base.decode64(signature) do
      {:ok, binary_sig} -> signature_length = byte_size(binary_sig)
        case signature_length do
          64 -> Base.encode64(signature)
          _ -> to_raw_signature(signature)
        end
      _ -> ""
    end

    xml_document = ExCryptoSign.XmlDocument.parse_document(xml_string)
    xml_document = ExCryptoSign.XmlDocument.put_signature_value(xml_document, signature_value)
    ExCryptoSign.XmlDocument.build_xml(xml_document)
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

    File.write!("test/files/canonicalized.xml", canon)



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

  def canonicalize(xml, :exclusive), do: xml |> XmerlC14n.canonicalize!()
  def canonicalize(_xml, _), do: ""

end
