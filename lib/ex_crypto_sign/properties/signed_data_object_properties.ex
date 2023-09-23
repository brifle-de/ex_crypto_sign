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


  def parse_document(xml_document) do
    data_object_format = SweetXml.xpath(xml_document, SweetXml.sigil_x("//ds:Signature/ds:Object/ds:QualifyingProperties/ds:SignedProperties/ds:SignedDataObjectProperties/ds:DataObjectFormat", 's')) |> String.trim()
    commitment_type_indication = SweetXml.xpath(xml_document, SweetXml.sigil_x("//ds:Signature/ds:Object/ds:QualifyingProperties/ds:SignedProperties/ds:SignedDataObjectProperties/ds:CommitmentTypeIndication", 's')) |> String.trim()
    all_data_objects_time_stamp = SweetXml.xpath(xml_document, SweetXml.sigil_x("//ds:Signature/ds:Object/ds:QualifyingProperties/ds:SignedProperties/ds:SignedDataObjectProperties/ds:AllDataObjectsTimeStamp", 's')) |> String.trim()
    individual_data_objects_time_stamp = SweetXml.xpath(xml_document, SweetXml.sigil_x("//ds:Signature/ds:Object/ds:QualifyingProperties/ds:SignedProperties/ds:SignedDataObjectProperties/ds:IndividualDataObjectsTimeStamp", 's')) |> String.trim()

    %{
      data_object_format: data_object_format,
      commitment_type_indication: commitment_type_indication,
      all_data_objects_time_stamp: all_data_objects_time_stamp,
      individual_data_objects_time_stamp: individual_data_objects_time_stamp
    }
  end

  @doc """
  puts the data object format in the signed data object properties
  """

  def put_data_object_format(signed_data_object_properties, nil), do: Map.put(signed_data_object_properties, :data_object_format, nil)
  def put_data_object_format(signed_data_object_properties, %{object_reference: object_reference, mime_type: mime_type, encoding: encoding, object_identifier: object_identifier, description: description}) do
    put_data_object_format(signed_data_object_properties, object_reference, mime_type, encoding, object_identifier, description)
  end
  def put_data_object_format(signed_data_object_properties, map) when is_map(map) do
    %{
      object_reference: nil,
      mime_type: nil,
      encoding: nil,
      object_identifier: nil,
      description: nil
    }
    |> Map.merge(map)
    |> put_data_object_format(signed_data_object_properties)
  end
  def put_data_object_format(signed_data_object_properties, object_reference, mime_type, encoding, object_identifier, description) do
    xml = XmlBuilder.element("DataObjectFormat", %{"ObjectReference" => object_reference}, [
      XmlBuilder.element("MimeType", Enum.reject([mime_type], &is_nil/1)),
      XmlBuilder.element("Encoding", Enum.reject([encoding], &is_nil/1)),
      XmlBuilder.element("ObjectIdentifier", [
        XmlBuilder.element("Identifier", Enum.reject([object_identifier], &is_nil/1)),
        XmlBuilder.element("Description", Enum.reject([description], &is_nil/1))
      ])
    ])
    Map.put(signed_data_object_properties, :data_object_format, xml)
  end


  @doc """
  puts the commitment type indication in the signed data object properties
  """
  def put_commitment_type_indication(signed_data_object_properties, nil), do: Map.put(signed_data_object_properties, :commitment_type_indication, nil)
  def put_commitment_type_indication(signed_data_object_properties, %{commitment_type_identifier: commitment_type_identifier, commitment_type_qualifier: commitment_type_qualifier}) do
    put_commitment_type_indication(signed_data_object_properties, commitment_type_identifier, commitment_type_qualifier)
  end
  def put_commitment_type_indication(signed_data_object_properties, commitment_type_identifier, commitment_type_qualifier) do
    xml = XmlBuilder.element("CommitmentTypeIndication", [
      XmlBuilder.element("CommitmentTypeId", [
        XmlBuilder.element("Identifier", [
          commitment_type_identifier
        ]),
        XmlBuilder.element("Description", [
          commitment_type_qualifier
        ])
      ]),
      XmlBuilder.element("AllSignedDataObjects", [])
    ])
    Map.put(signed_data_object_properties, :commitment_type_indication, xml)
  end

  @doc """
  puts the all data objects time stamp in the signed data object properties
  """
  def put_all_data_objects_time_stamp(signed_data_object_properties, nil), do: Map.put(signed_data_object_properties, :all_data_objects_time_stamp, nil)
  def put_all_data_objects_time_stamp(signed_data_object_properties, %{time_stamp: time_stamp}) do
    put_all_data_objects_time_stamp(signed_data_object_properties, time_stamp)
  end
  def put_all_data_objects_time_stamp(signed_data_object_properties, time_stamp) do
    xml = XmlBuilder.element("AllDataObjectsTimeStamp", [
      XmlBuilder.element("EncapsulatedTimeStamp", [
        time_stamp
      ])
    ])
    Map.put(signed_data_object_properties, :all_data_objects_time_stamp, xml)
  end

  @doc """
  puts the individual data objects time stamp in the signed data object properties
  """
  def put_individual_data_objects_time_stamp(signed_data_object_properties, nil), do: Map.put(signed_data_object_properties, :individual_data_objects_time_stamp, nil)
  def put_individual_data_objects_time_stamp(signed_data_object_properties, %{object_reference: object_reference, time_stamp: time_stamp}) do
    put_individual_data_objects_time_stamp(signed_data_object_properties, object_reference, time_stamp)
  end
  def put_individual_data_objects_time_stamp(signed_data_object_properties, object_reference, time_stamp) do
    xml = XmlBuilder.element("IndividualDataObjectsTimeStamp", %{"ObjectReference" => object_reference}, [
      XmlBuilder.element("EncapsulatedTimeStamp", [
        time_stamp
      ])
    ])
    Map.put(signed_data_object_properties, :individual_data_objects_time_stamp, xml)
  end

  def build(nil), do: build(new())

  def build(signed_data_object_properties) do
    xml = XmlBuilder.element("SignedDataObjectProperties", [
      signed_data_object_properties.data_object_format,
      signed_data_object_properties.commitment_type_indication,
      signed_data_object_properties.all_data_objects_time_stamp,
      signed_data_object_properties.individual_data_objects_time_stamp
    ]
      |> Enum.filter(fn x -> x != nil end))
    xml
  end

  def build_xml(signed_data_object_properties), do: build(signed_data_object_properties) |> XmlBuilder.generate()

end
