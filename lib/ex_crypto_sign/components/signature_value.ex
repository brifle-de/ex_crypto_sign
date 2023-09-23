defmodule ExCryptoSign.Components.SignatureValue do
  def new() do
    %{
      value: nil,
    }
  end

  def new(value) do
    %{
      value: value,
    }
  end

  def parse_document(xml_document) do
    signature_value = SweetXml.xpath(xml_document, SweetXml.sigil_x("//ds:Signature/ds:SignatureValue/text()", 's')) |> String.trim()

    %{
      value: signature_value
    }
  end

  def put_value(signature_value, value) do
    Map.put(signature_value, :value, value)
  end

  def build(signature_value) do
    value = Map.get(signature_value, :value)

    # avoid nil values
    signature_val = case value do
      nil -> ""
      v -> v
    end


    signature_value_xml = XmlBuilder.element("ds:SignatureValue", [
      signature_val
    ])

    signature_value_xml
  end

  def build_xml(signature_value) do
    build(signature_value) |> XmlBuilder.generate()
  end

end
