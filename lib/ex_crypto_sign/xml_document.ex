defmodule ExCryptoSign.XmlDocument do

  # follows https://www.w3.org/TR/XAdES/

  alias ExCryptoSign.Constants.CanonicalizationMethods
  alias ExCryptoSign.Properties.SignedSignatureProperties
  alias ExCryptoSign.Constants.{HashMethods, SignatureMethods}

  alias ExCryptoSign.Components.{PropertiesObject, SignatureValue, SignedInfo, KeyInfo}

  @default_canal_method CanonicalizationMethods.get_exclusive()

  @doc """

  object: PropertiesObject
  signature_value: SignatureValue
  signed_info: SignedInfo
  key_info: KeyInfo

  """

  def new(id, opts \\ []) do
    %{
      id: id,
      object: Keyword.get(opts, :object, PropertiesObject.new()),
      signature_value: Keyword.get(opts, :signature_value, SignatureValue.new()),
      signed_info: Keyword.get(opts, :signed_info, SignedInfo.new()),
      key_info: Keyword.get(opts, :key_info, nil),
    }
  end

  @doc """
  puts the key info in the xml document options
  """
  def put_key_info(xml_document_options, key_info) do
    Map.put(xml_document_options, :key_info, key_info)
  end

  @doc """
  puts the object in the xml document options
  """
  def put_object(xml_document_options, object) do
    Map.put(xml_document_options, :object, object)
  end

  def put_signature_value(xml_document_options, signature_value) when is_binary(signature_value) do
    Map.put(xml_document_options, :signature_value, SignatureValue.new(signature_value))
  end

  @doc """
  puts the signature value in the xml document options
  """
  def put_signature_value(xml_document_options, signature_value) do
    Map.put(xml_document_options, :signature_value, signature_value)
  end


  @doc """
  puts the signed info in the xml document options
  """
  def put_signed_info(xml_document_options, signed_info) do
    Map.put(xml_document_options, :signed_info, signed_info)
  end

  def build_signature(xml_document) do
    XmlBuilder.element("ds:Signature", %{id: xml_document.id}, [
      SignedInfo.build(xml_document.signed_info),
      SignatureValue.build(xml_document.signature_value),
      PropertiesObject.build(xml_document.object, xml_document.id),
      KeyInfo.build(xml_document.key_info)
    ])
  end

  @doc """
  builds the xml object
  """
  def build(xml_document) do

    type_def = %{
      "targetNamespace" => "http://uri.etsi.org/01903/v1.1.1\#",
      "xmlns:xsd" => "http://www.w3.org/2001/XMLSchema",
      "xmlns" => "http://uri.etsi.org/01903/v1.1.1\#",
      "xmlns:ds" => "http://www.w3.org/2000/09/xmldsig\#",
      "elementFormDefault" => "qualified"
    }

    signature = build_signature(xml_document)

    meta = XmlBuilder.element("Metadata", [
      XmlBuilder.element("version", "1.0"),
    ])

    XmlBuilder.element("SignatureDocument", type_def, [meta, signature])


  end



  @doc """
  builds the xml object as string
  """
  def build_xml(xml_document) do
    XmlBuilder.document(build(xml_document))
    |> XmlBuilder.generate(encoding: "UTF-8")
    |> :binary.bin_to_list # convert to binary list to avoid encoding issues
    |> :xmerl_scan.string(namespace_conformant: true, document: true)
    |> then(fn {doc, _} -> doc end)
    |> XmerlC14n.canonicalize!()
    |> to_string()
  end

  @spec parse_document(any()) :: %{
          id: any(),
          key_info: any(),
          object: any(),
          signature_value: any(),
          signed_info: any()
        }
  def parse_document(xml_string) do
    xml_document = SweetXml.parse(xml_string, namespace_conformant: true, document: true)

    id = SweetXml.xpath(xml_document, SweetXml.sigil_x("//ds:Signature/@id", 's'))
    signed_info = SignedInfo.parse_document(id, xml_document)
    signature_value = SignatureValue.parse_document(xml_document)
    key_info = KeyInfo.parse_document(xml_document)
    object = PropertiesObject.parse_document(xml_document)

    new(id,
      signed_info: signed_info,
      signature_value: signature_value,
      key_info: key_info,
      object: object
    )



  end

  def write_to_file!(xml_document, file_name) when is_binary(xml_document) do
    File.write!(file_name, xml_document)
  end

  def write_to_file!(xml_document, file_name) do
    xml_document
    |> build_xml()
    |> write_to_file!(file_name)
  end




end
