defmodule ExCryptoSign.Properties.SignedDataObjectProperties do

  def new() do
    %{
      data_object_format: nil,
      commitment_type_indication: nil,
      all_data_objects_time_stamp: nil,
      individual_data_objects_time_stamp: nil
    }
  end

  def new(map) when is_map(map) do
    new()
    |> put_data_object_format(Map.get(map,:data_object_format))
    |> put_commitment_type_indication(Map.get(map,:commitment_type_indication))
    |> put_all_data_objects_time_stamp(Map.get(map,:all_data_objects_time_stamp))
    |> put_individual_data_objects_time_stamp(Map.get(map,:individual_data_objects_time_stamp))
  end


  defp parse_data_object_format(xml_document) do



    base = "//ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedDataObjectProperties"

    count = SweetXml.xpath(xml_document, SweetXml.sigil_x("#{base}/xades:DataObjectFormat", 'l')) |> Enum.count()



    data_object_format = SweetXml.xpath(xml_document, SweetXml.sigil_x("#{base}/xades:DataObjectFormat", 'l')) |> Enum.map(fn element ->

      reference_exist? = SweetXml.xpath(element, SweetXml.sigil_x("./@ObjectReference")) != nil
      identifier_exist? = SweetXml.xpath(element, SweetXml.sigil_x("./xades:ObjectIdentifier/xades:Identifier/text()")) != nil
      mime_type_exist? = SweetXml.xpath(element, SweetXml.sigil_x("./xades:MimeType/text()")) != nil
      encoding_exist? = SweetXml.xpath(element, SweetXml.sigil_x("./xades:Encoding/text()")) != nil
      description_exist? = SweetXml.xpath(element, SweetXml.sigil_x("./xades:ObjectIdentifier/xades:Description/text()")) != nil



      object_reference = if reference_exist?, do:  SweetXml.xpath(element, SweetXml.sigil_x("./@ObjectReference", 's')) |> String.trim(), else: nil
      object_identifier = if identifier_exist?, do: SweetXml.xpath(element, SweetXml.sigil_x("./xades:ObjectIdentifier/xades:Identifier/text()", 's')) |> String.trim(), else: nil
      mime_type = if mime_type_exist?, do: SweetXml.xpath(element, SweetXml.sigil_x("./xades:MimeType/text()", 's')) |> String.trim(), else: nil
      encoding = if encoding_exist?, do: SweetXml.xpath(element, SweetXml.sigil_x("./xades:Encoding/text()", 's')) |> String.trim(), else: nil
      description = if description_exist?, do: SweetXml.xpath(element, SweetXml.sigil_x("./xades:ObjectIdentifier/xades:Description/text()", 's')) |> String.trim(), else: nil


      has_any? = reference_exist? || identifier_exist? || mime_type_exist? || encoding_exist? || description_exist?



      case has_any? do
        true ->  %{
          object_reference: object_reference,
          mime_type: mime_type,
          encoding: encoding,
          object_identifier: object_identifier,
          description: description
        }
        false -> nil
      end
    end)
    |> Enum.filter(fn x -> x != nil end)




  end

  defp parse_commitment_type_indication(xml_document) do
    base = "//ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedDataObjectProperties"

    type_identifier_exist? = SweetXml.xpath(xml_document, SweetXml.sigil_x("#{base}/xades:CommitmentTypeIndication/xades:CommitmentTypeId/xades:Identifier/text()")) != nil
    type_qualifier_exist? = SweetXml.xpath(xml_document, SweetXml.sigil_x("#{base}/xades:CommitmentTypeIndication/xades:CommitmentTypeId/xades:Description/text()")) != nil

    commitment_type_identifier = if type_identifier_exist?, do: SweetXml.xpath(xml_document, SweetXml.sigil_x("#{base}/xades:CommitmentTypeIndication/xades:CommitmentTypeId/xades:Identifier/text()", 's')) |> String.trim(), else: nil
    commitment_type_qualifier = if type_qualifier_exist?, do: SweetXml.xpath(xml_document, SweetXml.sigil_x("#{base}/xades:CommitmentTypeIndication/xades:CommitmentTypeId/xades:Description/text()", 's')) |> String.trim(), else: nil

    has_any? = type_identifier_exist? || type_qualifier_exist?
    case has_any? do
      true -> %{
        commitment_type_identifier: commitment_type_identifier,
        commitment_type_qualifier: commitment_type_qualifier
      }
      false -> nil
    end

  end

  defp parse_all_data_objects_time_stamp(xml_document) do

    base = "//ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedDataObjectProperties"

    time_stamp_exist? = SweetXml.xpath(xml_document, SweetXml.sigil_x("#{base}/xades:AllDataObjectsTimeStamp/xades:EncapsulatedTimeStamp/text()")) != nil

    time_stamp = if time_stamp_exist?, do: SweetXml.xpath(xml_document, SweetXml.sigil_x("#{base}/xades:AllDataObjectsTimeStamp/xades:EncapsulatedTimeStamp/text()", 's')) |> String.trim(), else: nil

    has_any? = time_stamp_exist?

    case has_any? do
      true -> %{
        time_stamp: time_stamp
      }
      false -> nil
    end

  end

  defp parse_individual_data_objects_time_stamp(xml_document) do

    base = "//ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedDataObjectProperties"

    reference_exist? = SweetXml.xpath(xml_document, SweetXml.sigil_x("#{base}/xades:IndividualDataObjectsTimeStamp/@ObjectReference")) != nil
    time_stamp_exist? = SweetXml.xpath(xml_document, SweetXml.sigil_x("#{base}/xades:IndividualDataObjectsTimeStamp/xades:EncapsulatedTimeStamp/text()")) != nil

    object_reference = if reference_exist?, do: SweetXml.xpath(xml_document, SweetXml.sigil_x("#{base}/xades:IndividualDataObjectsTimeStamp/@ObjectReference", 's')) |> String.trim(), else: nil
    time_stamp = if time_stamp_exist?, do: SweetXml.xpath(xml_document, SweetXml.sigil_x("#{base}/xades:IndividualDataObjectsTimeStamp/xades:EncapsulatedTimeStamp/text()", 's')) |> String.trim(), else: nil


    has_any? = reference_exist? || time_stamp_exist?

    case has_any? do
      true -> %{
        object_reference: object_reference,
        time_stamp: time_stamp
      }
      false -> nil
    end


  end


  def parse_document(xml_document) do
    data_object_format = parse_data_object_format(xml_document)
    commitment_type_indication = parse_commitment_type_indication(xml_document)
    all_data_objects_time_stamp = parse_all_data_objects_time_stamp(xml_document)
    individual_data_objects_time_stamp = parse_individual_data_objects_time_stamp(xml_document)

    new(%{
      data_object_format: data_object_format,
      commitment_type_indication: commitment_type_indication,
      all_data_objects_time_stamp: all_data_objects_time_stamp,
      individual_data_objects_time_stamp: individual_data_objects_time_stamp
    })
  end

  @doc """
  puts the data object format in the signed data object properties
  """

  def put_data_object_format(signed_data_object_properties, nil), do: Map.put(signed_data_object_properties, :data_object_format, nil)

  def put_data_object_format(sign_data_object_properties, data_object_format) when is_list(data_object_format) do

    data = Enum.map(data_object_format, fn element ->
      %{
        object_reference: nil,
        mime_type: nil,
        encoding: nil,
        object_identifier: nil,
        description: nil
      }
      |> Map.merge(element)
    end)

    Map.put(sign_data_object_properties, :data_object_format, data)
  end

  def put_data_object_format(signed_data_object_properties, map) when is_map(map) do
    data = %{
      object_reference: nil,
      mime_type: nil,
      encoding: nil,
      object_identifier: nil,
      description: nil
    }
    |> Map.merge(map)

    Map.put(signed_data_object_properties, :data_object_format, [data])
  end
  def build_data_object_format(signed_data_object_properties) do

    Enum.map(signed_data_object_properties.data_object_format, fn element ->


      obj_ref = if element.object_reference != nil do
        element.object_reference
      else
        ""
      end

      mime = if element.mime_type != nil do
        XmlBuilder.element("xades:MimeType", [
          element.mime_type
        ])
      else
        nil
      end

      encoding = if element.encoding != nil do
        XmlBuilder.element("xades:Encoding", [
          element.encoding
        ])
      else
        nil
      end

      identifier = if element.object_identifier != nil do
        XmlBuilder.element("xades:Identifier", [
          element.object_identifier
        ])
      else
        nil
      end

      description = if element.description != nil do
        XmlBuilder.element("xades:Description", [
          element.description
        ])
      else
        nil
      end


      xml = XmlBuilder.element("xades:DataObjectFormat",
      [
        ObjectReference: obj_ref
      ],
      [
        XmlBuilder.element("xades:ObjectIdentifier", [
          [identifier, description] |> Enum.filter(fn x -> x != nil end)
        ]),
        mime,
        encoding,
      ] |> Enum.filter(fn x -> x != nil end)
      )
      xml
    end
    )


  end


  @doc """
  puts the commitment type indication in the signed data object properties
  """
  def put_commitment_type_indication(signed_data_object_properties, nil), do: Map.put(signed_data_object_properties, :commitment_type_indication, nil)
  def put_commitment_type_indication(signed_data_object_properties, map) do
    data = %{
      commitment_type_identifier: nil,
      commitment_type_qualifier: nil,
    }
    |> Map.merge(map)

    Map.put(signed_data_object_properties, :commitment_type_indication, data)
  end
  @spec build_commitment_type_indication(
          atom
          | %{:commitment_type_indication => any, optional(any) => any}
        ) :: list | {any, any, any}
  def build_commitment_type_indication(signed_data_object_properties) do

    if signed_data_object_properties.commitment_type_indication != nil do
      identifier = if signed_data_object_properties.commitment_type_indication.commitment_type_identifier != nil
      do
        XmlBuilder.element("xades:Identifier", [
          signed_data_object_properties.commitment_type_indication.commitment_type_identifier
        ])
      else
        nil
      end

      description = if signed_data_object_properties.commitment_type_indication.commitment_type_qualifier != nil
      do
        XmlBuilder.element("xades:Description", [
          signed_data_object_properties.commitment_type_indication.commitment_type_qualifier
        ])
      else
        nil
      end

      type_id = [XmlBuilder.element("xades:Identifier", [
        identifier
      ]),
      XmlBuilder.element("xades:Description", [
        description
      ])] |> Enum.filter(fn x -> x != nil end)

      XmlBuilder.element("xades:CommitmentTypeIndication", [
        XmlBuilder.element("xades:CommitmentTypeId", type_id)
      ])
    else
      nil
    end

  end

  @doc """
  puts the all data objects time stamp in the signed data object properties
  """
  def put_all_data_objects_time_stamp(signed_data_object_properties, nil), do: Map.put(signed_data_object_properties, :all_data_objects_time_stamp, nil)
  def put_all_data_objects_time_stamp(signed_data_object_properties, map) do
    data = %{time_stamp: nil}
    |> Map.merge(map)
    Map.put(signed_data_object_properties, :all_data_objects_time_stamp, data)
  end
  def build_all_data_objects_time_stamp(signed_data_object_properties) do

    if signed_data_object_properties.all_data_objects_time_stamp == nil do
      nil
    else
      xml = XmlBuilder.element("xades:AllDataObjectsTimeStamp", [
        XmlBuilder.element("xades:EncapsulatedTimeStamp", [
          signed_data_object_properties.all_data_objects_time_stamp.time_stamp
        ])
      ])
      xml
    end

  end

  @doc """
  puts the individual data objects time stamp in the signed data object properties
  """
  def put_individual_data_objects_time_stamp(signed_data_object_properties, nil), do: Map.put(signed_data_object_properties, :individual_data_objects_time_stamp, nil)
  def put_individual_data_objects_time_stamp(signed_data_object_properties, map) do

    data = %{
        object_reference: nil,
        time_stamp: nil
      }
      |> Map.merge(map)

    Map.put(signed_data_object_properties, :individual_data_objects_time_stamp, data)
  end
  def build_individual_data_objects_time_stamp(signed_data_object_properties) do

    if signed_data_object_properties.individual_data_objects_time_stamp == nil do
      nil

    else
      xml = XmlBuilder.element("xades:IndividualDataObjectsTimeStamp", [
        XmlBuilder.element("xades:ObjectReference", [
          signed_data_object_properties.individual_data_objects_time_stamp.object_reference
        ]),
        XmlBuilder.element("xades:EncapsulatedTimeStamp", [
          signed_data_object_properties.individual_data_objects_time_stamp.time_stamp
        ])
      ])
      xml
    end


  end

  def build(nil), do: build(new())

  def build(signed_data_object_properties) do



    xml = XmlBuilder.element("xades:SignedDataObjectProperties", [
      build_data_object_format(signed_data_object_properties),
      build_commitment_type_indication(signed_data_object_properties),
      build_all_data_objects_time_stamp(signed_data_object_properties),
      build_individual_data_objects_time_stamp(signed_data_object_properties)
    ]
      |> Enum.filter(fn x -> x != nil end))
    xml
  end

  def build_xml(signed_data_object_properties), do: build(signed_data_object_properties) |> XmlBuilder.generate()

end
