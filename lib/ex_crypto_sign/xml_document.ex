defmodule ExCryptoSign.XmlDocument do

  # follows https://www.w3.org/TR/XAdES/

  alias Hex.API.Key
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
  embedded_documents: [EmbeddedDocument], %{id: "doc-1", content: "some content"}

  """
  def new(id, opts \\ []) do
    %{
      id: id,
      object: Keyword.get(opts, :object, PropertiesObject.new()),
      signature_value: Keyword.get(opts, :signature_value, SignatureValue.new()),
      signed_info: Keyword.get(opts, :signed_info, SignedInfo.new()),
      key_info: Keyword.get(opts, :key_info, nil),
      embedded_documents: Keyword.get(opts, :embedded_documents, []),
      meta: Keyword.get(opts, :meta, %{"version" => "1.0", "baseUrl" => "https://documents.brifle.de/"})
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
    run_build(xml_document, export_enabled: false)
  end

  defp run_build(xml_document, opts) do
    type_def = %{
      "targetNamespace" => "http://uri.etsi.org/01903/v1.1.1\#",
      "xmlns:xsd" => "http://www.w3.org/2001/XMLSchema",
      "xmlns" => "http://uri.etsi.org/01903/v1.1.1\#",
      "xmlns:ds" => "http://www.w3.org/2000/09/xmldsig\#",
      "elementFormDefault" => "qualified"
    }

    signature = build_signature(xml_document)

    metadata = xml_document.meta |> Enum.map(fn {key, value} ->
      XmlBuilder.element(key, value)
    end)

    meta = XmlBuilder.element("Metadata", metadata)

    has_embedded_documents? = xml_document.embedded_documents != []

    export_enabled = Keyword.get(opts, :export_content, false)

    export_data = if export_enabled do
      export_content = Keyword.get(opts, :export_content, %{})
      exp = Enum.map(export_content, fn {doc_url, doc_data} ->
        doc_id = doc_url |> String.split("/") |> List.last()
        XmlBuilder.element("SignatureContent", [URL: doc_url, id: "data-#{doc_id}"],  doc_data)
      end)
      [XmlBuilder.element("ContentExport", exp)]
    else
      []
    end

    if has_embedded_documents? do
        embs = Enum.map(xml_document.embedded_documents, fn doc ->
          XmlBuilder.element("SignatureContent", [ID: "data-content-#{doc.id}"],  doc.content)
        end)
        xml_embs = XmlBuilder.element("SignatureContents", embs)
        XmlBuilder.element("SignatureDocument", type_def, [meta, xml_embs, signature] ++ export_data)
      else
        XmlBuilder.element("SignatureDocument", type_def, [meta, signature] ++ export_data)
    end
  end

  @doc """
  builds the xml object and adds the content to the xml document
  """
  def export(xml_document, content) do
    run_build(xml_document, export_enabled: true, export_content: content)
    |> to_xml_string()
  end

  @doc """
  gets the document urls from the xml document
  """
  def parse_document_urls(xml_string) do
    urls = SweetXml.xpath(xml_string, SweetXml.sigil_x("//ds:SignedInfo/ds:Reference/@URI", 'ls')) || []
    Enum.filter(urls, fn url -> url != "#SignedProperties" end)
  end


  @doc """
  builds the xml object as string
  """
  def build_xml(xml_document) do
    to_xml_string(build(xml_document))
  end

  @spec to_xml_string(
          atom()
          | bitstring()
          | maybe_improper_list()
          | {any()}
          | {any(), any()}
          | {any(), any(), any()}
        ) :: binary()
  def to_xml_string(xml_document) do
    XmlBuilder.document(xml_document)
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
    meta = parse_metadata(xml_document)
    embedded_documents = SweetXml.xpath(xml_document, SweetXml.sigil_x("//SignatureContents/SignatureContent", 'l'))
      |> Enum.map(fn doc ->
        id = SweetXml.xpath(doc, SweetXml.sigil_x("@ID", 's')) |> String.replace("data-content-", "")
        content = SweetXml.xpath(doc, SweetXml.sigil_x("text()", 's'))
        %{id: id, content: content}
      end)

    new(id,
      signed_info: signed_info,
      signature_value: signature_value,
      key_info: key_info,
      object: object,
      meta: meta,
      embedded_documents: embedded_documents
    )

  end

  defp parse_metadata(xml_document) do
    version = SweetXml.xpath(xml_document, SweetXml.sigil_x("//Metadata/version/text()", 's')) || ""
    baseUrl = SweetXml.xpath(xml_document, SweetXml.sigil_x("//Metadata/baseUrl/text()", 's')) || ""
    %{"version" => version, "baseUrl" => baseUrl}
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
