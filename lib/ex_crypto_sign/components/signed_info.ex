defmodule ExCryptoSign.Components.SignedInfo do

  alias ExCryptoSign.Constants.CanonicalizationMethods
  alias ExCryptoSign.Constants.{HashMethods, SignatureMethods}
  alias ExCryptoSign.Components.PropertiesObject

  @default_canal_method CanonicalizationMethods.get_exclusive()

  def new(signature_id \\ "") do
    %{
      signature_id: signature_id,
      canonicalization_method: @default_canal_method,
      signature_method: nil,
      documents_digest: [],
      signed_property_digest: nil
    }
  end

  def parse_document(signature_id, xml_document) do
    canonicalization_method = SweetXml.xpath(xml_document, SweetXml.sigil_x("//ds:Signature/ds:SignedInfo/ds:CanonicalizationMethod/@Algorithm"))
    signature_method = SweetXml.xpath(xml_document, SweetXml.sigil_x("//ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm"))
      |> to_string()
      |> SignatureMethods.from_w3_url()

    references = SweetXml.xpath(xml_document, SweetXml.sigil_x("//ds:Signature/ds:SignedInfo/ds:Reference", 'l'))
    signed_property_digest = SweetXml.xpath(xml_document, SweetXml.sigil_x("//ds:Signature/ds:SignedInfo/ds:Reference[@URI='#SignedProperties']/ds:DigestMethod/@Algorithm", 's'))
    signed_property_digest_value = SweetXml.xpath(xml_document, SweetXml.sigil_x("//ds:Signature/ds:SignedInfo/ds:Reference[@URI='#SignedProperties']/ds:DigestValue/text()", 's')) |> String.trim()
    signed_property_digest_obj = %{
      id: nil,
      uri: "#SignedProperties",
      digest_method: signed_property_digest,
      digest_value: signed_property_digest_value |> Base.decode64!()
    }

    documents_digest = Enum.map(references, fn ref ->
      id = SweetXml.xpath(ref, SweetXml.sigil_x("./@ID", 's'))
      uri = SweetXml.xpath(ref, SweetXml.sigil_x("./@URI", 's'))
      digest_method = SweetXml.xpath(ref, SweetXml.sigil_x("./ds:DigestMethod/@Algorithm", 's'))
      digest_value = SweetXml.xpath(ref, SweetXml.sigil_x("./ds:DigestValue/text()", 's')) |> String.trim()
      %{
        id: id,
        uri: uri,
        digest_method: digest_method,
        digest_value: digest_value |> Base.decode64!()
      }
    end) |> Enum.filter(fn ref -> ref.uri != "#SignedProperties" end)

    %{
      signature_id: signature_id,
      canonicalization_method: canonicalization_method,
      signature_method: signature_method,
      documents_digest: documents_digest,
      signed_property_digest: signed_property_digest_obj
    }
  end

  def put_canonicalization_method(signed_info, canonicalization_method) do
    Map.put(signed_info, :canonicalization_method, canonicalization_method)
  end

  def put_signature_method(signed_info, signature_method) do
    Map.put(signed_info, :signature_method, signature_method)
  end

  def add_document_digest(signed_info, id, uri, digest_method, content) do

    digest_value = :crypto.hash(digest_method, content)
    digest_method_name = HashMethods.get_w3_url(digest_method)

    document_digest = %{
      id: id,
      uri: uri,
      digest_method: digest_method_name,
      digest_value: digest_value
    }

    document_digests = Map.get(signed_info, :documents_digest) ++ [document_digest]

    Map.put(signed_info, :documents_digest, document_digests)
  end


  @spec put_signed_property_digest(map, any, any) :: %{
          :signed_property_digest => %{
            digest_method: <<_::64, _::_*8>>,
            digest_value: any,
            uri: <<_::136>>
          },
          optional(any) => any
        }
  @spec put_signed_property_digest(map, any, any) :: %{
          :signed_property_digest => %{
            digest_method: <<_::64, _::_*8>>,
            digest_value: any,
            id: nil,
            uri: <<_::136>>
          },
          optional(any) => any
        }
  def put_signed_property_digest(signed_info, digest_method, signed_properties_map) when is_map(signed_properties_map) do
    xml = PropertiesObject.build_signature_xml(signed_properties_map)

    put_signed_property_digest(signed_info, digest_method, xml)
  end

  def put_signed_property_digest(signed_info, digest_method, signed_properties_xml) do

    digest_value = :crypto.hash(digest_method, signed_properties_xml)
    digest_method_name = HashMethods.get_w3_url(digest_method)
    signed_property_digest = %{
      id: nil,
      uri: "#SignedProperties",
      digest_method: digest_method_name,
      digest_value: digest_value
    }

    Map.put(signed_info, :signed_property_digest, signed_property_digest)
  end

  def get_document_digests(signed_info) do
    documents_digest = Map.get(signed_info, :documents_digest)
    Enum.map(documents_digest, fn doc -> {HashMethods.from_w3_url(doc.digest_method) , doc.digest_value }end)
  end

  @doc """
  checks if the signed info contains all the documents
  """
  def contains_documents?(signed_info, document_contents) do
    digests = get_document_digests(signed_info)

    # check if all documents are contained in the signed info
    document_contents
    |> Enum.all?(fn document ->
      # check if the document in contains in any of the digests of the signed info
      Enum.any?(digests, fn {digest_method, digest_value} ->
        digest_value == :crypto.hash(digest_method, document)
      end)
    end)
  end

  @doc """
  checks if the signed info contains the signed properties
  """
  def contains_signed_property?(signed_info, signed_properties_xml) do
    signed_property_digest = Map.get(signed_info, :signed_property_digest)
    signed_property_digest_value = signed_property_digest.digest_value |> Base.encode64()
    signed_property_digest_method = signed_property_digest.digest_method |> HashMethods.from_w3_url()

    expected_digest = :crypto.hash(signed_property_digest_method, signed_properties_xml) |> Base.encode64()

    signed_property_digest_value == expected_digest
  end




  def build(sign_info) do
    canonicalization_method = Map.get(sign_info, :canonicalization_method)
    signature_method = Map.get(sign_info, :signature_method)
    signature_method_name = SignatureMethods.get_w3_url(signature_method)
    documents_digest = Map.get(sign_info, :documents_digest)
    signed_property_digest = Map.get(sign_info, :signed_property_digest)

    canonicalization_method_xml = XmlBuilder.element("ds:CanonicalizationMethod", %{"Algorithm" => canonicalization_method})

    signature_method_xml = XmlBuilder.element("ds:SignatureMethod", %{"Algorithm" => signature_method_name})

    refs = documents_digest ++ [signed_property_digest]


    # build the references based on the documents digest and the signed property digest
    references_xml = Enum.map(refs, fn ref ->
      uri = ref.uri
      digest_method = ref.digest_method
      digest_value = ref.digest_value
      id = ref.id

      digest_method_xml = XmlBuilder.element("ds:DigestMethod",%{"Algorithm" => digest_method})

      digest_value_xml = XmlBuilder.element("ds:DigestValue", [
        digest_value |> Base.encode64()
      ])

      attributes = case id do
        nil -> %{"URI" => uri}
        _ -> %{"URI" => uri, "ID" => id}
      end

      XmlBuilder.element("ds:Reference", attributes, [
        digest_method_xml,
        digest_value_xml
      ])
    end)



    signed_info_xml = XmlBuilder.element("ds:SignedInfo", [
      canonicalization_method_xml,
      signature_method_xml,
      references_xml
    ])

    signed_info_xml
  end

  def build_xml(sign_info) do
    signed_info_xml = build(sign_info)
    signed_info_xml
    |> XmlBuilder.generate()
  end

end
