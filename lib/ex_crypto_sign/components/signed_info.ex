defmodule ExCryptoSign.Components.SignedInfo do

  alias EllipticCurve.Utils.Base64
  alias ExCryptoSign.Constants.TransformMethods
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
    signed_property_transforms = SweetXml.xpath(xml_document, SweetXml.sigil_x("//ds:Signature/ds:SignedInfo/ds:Reference[@URI='#SignedProperties']/ds:Transforms/ds:Transform", 'l'))

      |> Enum.map(fn x ->
        algorithm = SweetXml.xpath(x, SweetXml.sigil_x("./@Algorithm", 's')) |> TransformMethods.from_w3_url()
        value = SweetXml.xpath(x, SweetXml.sigil_x("./ds:XPath/text()", 's'))
        case algorithm do
          :xpath -> {:xpath, value}
          _ -> algorithm
        end
      end)

    signed_property_digest_obj = %{
      id: nil,
      uri: "#SignedProperties",
      digest_method: signed_property_digest,
      digest_value: signed_property_digest_value |> Base.decode64!(),
      transforms: signed_property_transforms
    }

    documents_digest = Enum.map(references, fn ref ->
      id = SweetXml.xpath(ref, SweetXml.sigil_x("./@Id", 's'))
      uri = SweetXml.xpath(ref, SweetXml.sigil_x("./@URI", 's'))
      digest_method = SweetXml.xpath(ref, SweetXml.sigil_x("./ds:DigestMethod/@Algorithm", 's'))
      digest_value = SweetXml.xpath(ref, SweetXml.sigil_x("./ds:DigestValue/text()", 's')) |> String.trim()
      transforms = SweetXml.xpath(ref, SweetXml.sigil_x("./ds:Transforms/ds:Transform", 'l'))
        |> Enum.map(fn x ->
          algorithm = SweetXml.xpath(x, SweetXml.sigil_x("./@Algorithm", 's')) |> TransformMethods.from_w3_url()
          value = SweetXml.xpath(x, SweetXml.sigil_x("./ds:XPath/text()", 's'))
          case algorithm do
            :xpath -> {:xpath, value}
            _ -> algorithm
          end
        end)
      %{
        id: id,
        uri: uri,
        digest_method: digest_method,
        transforms: transforms,
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

    data_id = uri |> String.split("/") |> List.last() |> String.replace_prefix("#", "") |> String.replace_prefix("data-", "")
    document = %{
      id: data_id,
      content: content,
    }
    digest_value = compute_document_hash(document, digest_method)
    digest_method_name = HashMethods.get_w3_url(digest_method)

    document_digest = %{
      id: id,
      uri: uri,
      digest_method: digest_method_name,
      digest_value: digest_value,
      transforms: [:c14n]
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
    xml = compute_signed_prop_xml(signed_properties_map)

    put_signed_property_digest(signed_info, digest_method, xml)
  end

  def put_signed_property_digest(signed_info, digest_method, signed_properties_xml) do
    digest_value = :crypto.hash(digest_method, signed_properties_xml)
    digest_method_name = HashMethods.get_w3_url(digest_method)
    signed_property_digest = %{
      id: nil,
      uri: "#SignedProperties",
      digest_method: digest_method_name,
      digest_value: digest_value,
      transforms: [:c14n]
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
        digest_value == compute_document_hash(document, digest_method)
      end)
    end)
  end

  defp compute_document_hash(document, digest_method) do
    content = XmlBuilder.element("SignatureContent", [id: "data-#{document.id}"],  document.content)
    |> XmlBuilder.generate(encoding: "UTF-8")
    |> String.replace("<SignatureContent", "<SignatureContent xmlns=\"http://uri.etsi.org/01903/v1.1.1#\"")
    |> XmerlC14n.canonicalize!()
    hash = :crypto.hash(digest_method, content)
    hash
  end

  defp compute_signed_prop_xml(%{} = signed_properties_map) do

    xml = PropertiesObject.build_signature_xml(signed_properties_map)
      |> String.replace("<xades:SignedProperties", "<?xml version=\"1.0\"?><xades:SignedProperties xmlns:xades=\"http://uri.etsi.org/01903/v1.3.2#\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"")
      # prepend xml utf-8 encoding
      |> String.replace("<?xml version=\"1.0\"?>", "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
      |> SweetXml.parse(namespace_conformant: true, document: true)
      |> XmerlC14n.canonicalize!(false)

      # add intend, for fixing the canonicalization problem
      intend = String.replace(xml, "\n", "\n        ")

      File.write!("signed_prop.xml", intend)

      intend
  end

  defp compute_signed_prop_xml(signed_properties_xml) do


    xml = signed_properties_xml
    |> String.replace("<xades:SignedProperties", "<?xml version=\"1.0\"?><xades:SignedProperties xmlns:xades=\"http://uri.etsi.org/01903/v1.3.2#\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"")
    |> String.replace("<?xml version=\"1.0\"?>", "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
    |> SweetXml.parse(namespace_conformant: true, document: true)
    |> XmerlC14n.canonicalize!(false)

    # add intend, for fixing the canonicalization problem
    intend = String.replace(xml, "\n", "\n        ")

    intend

  end

  @doc """
  checks if the signed info contains the signed properties
  """
  def contains_signed_property?(signed_info, signed_properties_xml) do
    signed_property_digest = Map.get(signed_info, :signed_property_digest)
    signed_property_digest_value = signed_property_digest.digest_value |> Base.encode64()
    signed_property_digest_method = signed_property_digest.digest_method |> HashMethods.from_w3_url()

    expected_digest = :crypto.hash(signed_property_digest_method, compute_signed_prop_xml(signed_properties_xml)) |> Base.encode64()

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

      # transforms
      transforms = Enum.map(ref.transforms, fn transform ->
        case transform do
          :c14n -> XmlBuilder.element("ds:Transform", %{"Algorithm" => TransformMethods.get_c14n()})
          {:xpath, xpath} -> XmlBuilder.element("ds:Transform", %{"Algorithm" => TransformMethods.get_xpath()}, [
            XmlBuilder.element("ds:XPath", xpath)
          ])
          _ -> XmlBuilder.element("ds:Transform", %{"Algorithm" => transform})
          end
      end)

      transform = case transforms do
        [] -> nil
        _ -> XmlBuilder.element("ds:Transforms", transforms)
      end

      attributes = case id do
        nil -> %{"URI" => uri}
        _ -> %{"URI" => uri, "Id" => id}
      end

      XmlBuilder.element("ds:Reference", attributes, [
        transform,
        digest_method_xml,
        digest_value_xml
      ] |> Enum.filter(fn x -> x != nil end))
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
