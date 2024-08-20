defmodule ExCryptoSign.Properties.SignedSignatureProperties do
  alias ExCryptoSign.Constants.HashMethods
  def new() do

    # use implient policy



    %{
      signing_time: nil,
      signing_certificate: nil,
      signature_policy_identifier: "xades:SignaturePolicyImplied",
      signature_production_place: nil,
      signer_role: nil
    }
  end

  @spec new(map) :: %{
          signature_policy_identifier: list | {any, any, any},
          signature_production_place: nil,
          signer_role: nil,
          signing_certificate: nil,
          signing_time: nil
        }
  def new(map_opts) when is_map(map_opts) do


    new()
    |> put_signature_production_place(Map.get(map_opts,:signature_production_place))
    |> put_signer_role(Map.get(map_opts,:signer_role))
    |> put_x590_certificate(Map.get(map_opts,:signing_certificate))
    |> put_signing_time(Map.get(map_opts,:signing_time))

  end

  defp parse_certificate(xml_document) do
    base = "//ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningCertificate/xades:Cert"
    digest_method = SweetXml.xpath(xml_document, SweetXml.sigil_x("#{base}/xades:CertDigest/ds:DigestMethod/@Algorithm", 's')) |> HashMethods.from_w3_url()
    digest_value = SweetXml.xpath(xml_document, SweetXml.sigil_x("#{base}/xades:CertDigest/ds:DigestValue/text()", 's')) |> String.trim()
    issuer_name = SweetXml.xpath(xml_document, SweetXml.sigil_x("#{base}/xades:IssuerSerial/ds:X509IssuerName/text()", 's')) |> String.trim()
    serial_number = SweetXml.xpath(xml_document, SweetXml.sigil_x("#{base}/xades:IssuerSerial/ds:X509SerialNumber/text()", 's')) |> String.trim()

    %{
      digest_type: digest_method,
      digest: digest_value,
      issuer: issuer_name,
      serial: serial_number
    }
  end

  def parse_document(xml_document) do

    base = "//ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties"

    signing_time = SweetXml.xpath(xml_document, SweetXml.sigil_x("#{base}/xades:SigningTime/text()", 's')) |> String.trim()
    signing_certificate = parse_certificate(xml_document)
    signature_production_place_city = SweetXml.xpath(xml_document, SweetXml.sigil_x("#{base}/xades:SignatureProductionPlace/xades:City/text()", 's')) |> String.trim()
    signature_production_place_country = SweetXml.xpath(xml_document, SweetXml.sigil_x("#{base}/xades:SignatureProductionPlace/xades:CountryName/text()", 's')) |> String.trim()
    signer_roles_claimed = SweetXml.xpath(xml_document, SweetXml.sigil_x("#{base}/xades:SignerRole/xades:ClaimedRoles/xades:ClaimedRole", 'l'))
    signer_roles_certified = SweetXml.xpath(xml_document, SweetXml.sigil_x("#{base}/xades:SignerRole/xades:CertifiedRoles/xades:CertifiedRole", 'l'))

    signer_role = %{
      claimed_roles: Enum.map(signer_roles_claimed, fn role -> SweetXml.xpath(role, SweetXml.sigil_x("./text()", 's')) |> String.trim() end),
      certified_roles: Enum.map(signer_roles_certified, fn role -> SweetXml.xpath(role, SweetXml.sigil_x("./text()", 's')) |> String.trim() end)
    }


    new(%{
      signing_time: signing_time,
      signing_certificate: signing_certificate,
      signature_production_place: %{
        city_name: signature_production_place_city,
        country: signature_production_place_country
      },
      signer_role: signer_role
    })

  end

  @spec put_signing_time(map, nil) :: %{:signing_time => nil, optional(any) => any}
  def put_signing_time(signature_properties, nil), do: Map.put(signature_properties, :signing_time, nil)
  def put_signing_time(signature_properties, %{signing_time: signing_time}) do
    Map.put(signature_properties, :signing_time, signing_time)
  end
  def put_signing_time(signature_properties, signing_time) do
    Map.put(signature_properties, :signing_time, signing_time)
  end

  def build_signing_time(signed_signature_properties) do

    if signed_signature_properties.signing_time == nil do
      nil
    else
      XmlBuilder.element("xades:SigningTime",
        signed_signature_properties.signing_time
      )
    end

  end


  def put_x590_certificate(signed_signature_properties, nil), do: Map.put(signed_signature_properties, :signing_certificate, nil)
  def put_x590_certificate(signed_signature_properties, map) when is_map(map) do
    values = %{
      issuer: nil,
      serial: nil,
      digest_type: nil,
      digest: nil
    }
    |> Map.merge(map)

    Map.put(signed_signature_properties, :signing_certificate, values)
  end

  def build_x590_certificate(signed_signature_properties) do

    if signed_signature_properties.signing_certificate == nil do
      nil
    else
      xml = XmlBuilder.element("xades:SigningCertificate", [
        XmlBuilder.element("xades:Cert", [
          XmlBuilder.element("xades:CertDigest", [
            XmlBuilder.element("ds:DigestMethod", %{Algorithm: HashMethods.get_w3_url(signed_signature_properties.signing_certificate.digest_type)}, []),
            XmlBuilder.element("ds:DigestValue",
              signed_signature_properties.signing_certificate.digest
            )
          ]),
          XmlBuilder.element("xades:IssuerSerial", [
            XmlBuilder.element("ds:X509IssuerName",
              signed_signature_properties.signing_certificate.issuer
            ),
            XmlBuilder.element("ds:X509SerialNumber",
              signed_signature_properties.signing_certificate.serial
            )
          ])
        ])
      ])

      xml
    end

  end


  def put_signature_production_place(signature_properties, nil), do: Map.put(signature_properties, :signature_production_place, nil)
  def put_signature_production_place(signature_properties, map) when is_map(map) do
    values = %{
      city_name: nil,
      country: nil
    }
    |> Map.merge(map)
    Map.put(signature_properties, :signature_production_place, values)
  end
  @doc """
  puts the signature production place in the signed signature properties
  """
  def build_signature_production_place(signed_signature_properties) do

    if(signed_signature_properties.signature_production_place == nil) do
      nil
    else
      XmlBuilder.element("xades:SignatureProductionPlace", [
        XmlBuilder.element("xades:City", [
          signed_signature_properties.signature_production_place.city_name
        ]),
        XmlBuilder.element("xades:CountryName", [
          signed_signature_properties.signature_production_place.country
        ])
      ])
    end

  end

  @doc """
  puts the signer role in the signed signature properties
  """
  def put_signer_role(signed_signature_properties, nil), do: Map.put(signed_signature_properties, :signer_role, nil)
  def put_signer_role(signed_signature_properties, map) when is_map(map) do
    values = %{
      claimed_roles: [],
      certified_roles: []
    }
    |> Map.merge(map)

    Map.put(signed_signature_properties, :signer_role, values)
  end
  def build_signer_role(signed_signature_properties) do


    if(signed_signature_properties.signer_role == nil) do
      nil
    else

      claimed_roles = signed_signature_properties.signer_role.claimed_roles
      certified_roles = signed_signature_properties.signer_role.certified_roles

      if claimed_roles == nil && certified_roles == nil do
        nil
      else

        certified = if length(certified_roles) == 0, do: nil, else: XmlBuilder.element("xades:CertifiedRoles", [
          Enum.map(certified_roles, fn role -> XmlBuilder.element("xades:CertifiedRole", [role]) end)
        ])

        xml = XmlBuilder.element("xades:SignerRole", [
          XmlBuilder.element("xades:ClaimedRoles", [
            Enum.map(claimed_roles, fn role -> XmlBuilder.element("xades:ClaimedRole", [role]) end)
          ]),
          certified
        ] |> Enum.filter(fn x -> x != nil end)
        )
        xml
      end
    end

  end

  def build(nil), do: build(new())

  def build(signed_signature_properties) do


    signature_policy_identifier = XmlBuilder.element("xades:SignaturePolicyIdentifier", [
      XmlBuilder.element(signed_signature_properties.signature_policy_identifier, [])
    ])


    xml = XmlBuilder.element("xades:SignedSignatureProperties", [
      build_signing_time(signed_signature_properties),
      build_x590_certificate(signed_signature_properties),
      signature_policy_identifier,
      build_signature_production_place(signed_signature_properties),
      build_signer_role(signed_signature_properties)
    ]
      |> Enum.filter(fn x -> x != nil end)
    )
    xml
  end

  @doc """
  builds the xml for the signed signature properties
  """
  def build_xml(signed_props) do
    build(signed_props)
    |> XmlBuilder.generate()
  end

end
