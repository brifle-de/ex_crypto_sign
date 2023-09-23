defmodule ExCryptoSign.Components.KeyInfo do
  def new() do
    %{
      x509_data: nil,
    }
  end

  def parse_document(xml_document) do
    x509_data = SweetXml.xpath(xml_document, SweetXml.sigil_x("//ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate/text()", 's')) |> String.trim()

    %{
      x509_data: x509_data
    }
  end

  @doc """
  puts the x509 data in the key info
  """
  def put_x509_data(key_info, x509_data_pem) do
    Map.put(key_info, :x509_data, x509_data_pem)
  end

  @doc """
  build the key info
  """
  def build(key_info) do
    x509_data = Map.get(key_info, :x509_data)

    x509_data_xml = XmlBuilder.element("ds:X509Data", [
      XmlBuilder.element("ds:X509Certificate", [
        x509_data
      ])
    ])

    key_info_xml = XmlBuilder.element("ds:KeyInfo", [
      x509_data_xml
    ])

    key_info_xml
  end

  @doc """
  build the key info as xml string
  """
  def build_xml(key_info) do
    build(key_info) |> XmlBuilder.generate()
  end
end
