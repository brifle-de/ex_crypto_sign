defmodule ExCryptoSign.Components.PropertiesObject do

  alias ExCryptoSign.Properties.{SignedDataObjectProperties, SignedSignatureProperties, UnsignedSignatureProperties}

  def new() do
    %{
      signed_signature_properties: nil,
      signed_data_object_properties: nil,
      unsigned_signature_properties: nil
    }
  end

  def parse_document(xml_document) do
   %{
      signed_signature_properties: SignedSignatureProperties.parse_document(xml_document),
      signed_data_object_properties: SignedDataObjectProperties.parse_document(xml_document),
      unsigned_signature_properties: UnsignedSignatureProperties.parse_document(xml_document)
   }
  end

  def put_signed_properties(properties_object, signed_signature_properties) do
    Map.put(properties_object, :signed_signature_properties, signed_signature_properties)
  end

  def put_signed_data_object_properties(properties_object, signed_data_object_properties) do
    Map.put(properties_object, :signed_data_object_properties, signed_data_object_properties)
  end

  def put_unsigned_signature_properties(properties_object, unsigned_signature_properties) do
    Map.put(properties_object, :unsigned_signature_properties, unsigned_signature_properties)
  end



  @spec build(
          atom
          | %{
              :signed_data_object_properties =>
                atom
                | %{
                    :all_data_objects_time_stamp => any,
                    :commitment_type_indication => any,
                    :data_object_format => any,
                    :individual_data_objects_time_stamp => any,
                    optional(any) => any
                  },
              :signed_signature_properties =>
                atom
                | %{
                    :signature_policy_identifier => any,
                    :signature_production_place => any,
                    :signer_role => any,
                    :signing_certificate => any,
                    :signing_time => any,
                    optional(any) => any
                  },
              :unsigned_signature_properties =>
                atom
                | %{
                    :archive_time_stamps => any,
                    :certificate_values => any,
                    :complete_certificate_refs => any,
                    :complete_revocation_refs => any,
                    :counter_signatures => any,
                    :revocation_values => any,
                    :sig_and_ref_time_stamps => any,
                    :signature_time_stamps => any,
                    optional(any) => any
                  },
              optional(any) => any
            },
          any
        ) :: list | {any, any, any}
  def build(properties_object, signature_id) do

    # build signed properties xml

    signed_properties = XmlBuilder.element("SignedProperties", [
      SignedSignatureProperties.build(properties_object.signed_signature_properties),
      SignedDataObjectProperties.build(properties_object.signed_data_object_properties)
    ])



    # build unsigned signature properties xml

    unsigned_props = XmlBuilder.element("UnsignedProperties", [
      UnsignedSignatureProperties.build(properties_object.unsigned_signature_properties)
      ]
    )


    # build qualifying properties xml


    target = "\##{signature_id}"

    attr_qualifying_properties = %{"Target" => target }
    qualifying_properties = XmlBuilder.element("QualifyingProperties", attr_qualifying_properties, [
      signed_properties,
      unsigned_props
    ])

    # build properties object xml

    properties_object_xml = XmlBuilder.element("ds:Object", [
      qualifying_properties
    ])



    properties_object_xml
  end

  @spec build_signature_xml(
          atom
          | %{
              :signed_data_object_properties =>
                atom
                | %{
                    :all_data_objects_time_stamp => any,
                    :commitment_type_indication => any,
                    :data_object_format => any,
                    :individual_data_objects_time_stamp => any,
                    optional(any) => any
                  },
              :signed_signature_properties =>
                atom
                | %{
                    :signature_policy_identifier => any,
                    :signature_production_place => any,
                    :signer_role => any,
                    :signing_certificate => any,
                    :signing_time => any,
                    optional(any) => any
                  },
              optional(any) => any
            }
        ) :: binary
  @doc """
  builds the signature xml. It returns the signed properties tag
  """
  def build_signature_xml(properties_object) do

    signed_properties = XmlBuilder.element("SignedProperties",
    [
      Id: "SignedProperties"
    ],
    [
      SignedSignatureProperties.build(properties_object.signed_signature_properties),
      SignedDataObjectProperties.build(properties_object.signed_data_object_properties)
    ])

    signed_properties |> XmlBuilder.generate()
  end

  def build_xml(properties_object, signature_id) do
    build(properties_object, signature_id) |> XmlBuilder.generate()
  end

end
