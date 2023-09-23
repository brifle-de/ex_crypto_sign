defmodule ExCryptoSign.Properties.SignedSignatureProperties do
  alias ExCryptoSign.Constants.HashMethods
  def new() do

    # use implient policy

    signature_policy_identifier = XmlBuilder.element("SignaturePolicyIdentifier", [
      XmlBuilder.element("SignaturePolicyImplied", [])
    ])

    %{
      signing_time: nil,
      signing_certificate: nil,
      signature_policy_identifier: signature_policy_identifier,
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
    base = "//ds:Signature/ds:Object/QualifyingProperties/SignedProperties/SignedSignatureProperties/SigningCertificate/Cert"
    digest_method = SweetXml.xpath(xml_document, SweetXml.sigil_x("#{base}/CertDigest/DigestMethod/@Algorithm", 's')) |> HashMethods.from_w3_url()
    digest_value = SweetXml.xpath(xml_document, SweetXml.sigil_x("#{base}/CertDigest/DigestValue/text()", 's')) |> String.trim()
    issuer_name = SweetXml.xpath(xml_document, SweetXml.sigil_x("#{base}/IssuerSerial/X509IssuerName/text()", 's')) |> String.trim()
    serial_number = SweetXml.xpath(xml_document, SweetXml.sigil_x("#{base}/IssuerSerial/X509SerialNumber/text()", 's')) |> String.trim()

    %{
      digest_type: digest_method,
      digest: digest_value,
      issuer: issuer_name,
      serial: serial_number
    }
  end

  def parse_document(xml_document) do

    base = "//ds:Signature/ds:Object/QualifyingProperties/SignedProperties/SignedSignatureProperties"

    signing_time = SweetXml.xpath(xml_document, SweetXml.sigil_x("#{base}/SigningTime/text()", 's')) |> String.trim()
    signing_certificate = parse_certificate(xml_document)
    signature_production_place_city = SweetXml.xpath(xml_document, SweetXml.sigil_x("#{base}/SignatureProductionPlace/City/text()", 's')) |> String.trim()
    signature_production_place_country = SweetXml.xpath(xml_document, SweetXml.sigil_x("#{base}/SignatureProductionPlace/CountryName/text()", 's')) |> String.trim()
    signer_roles_claimed = SweetXml.xpath(xml_document, SweetXml.sigil_x("#{base}/SignerRole/ClaimedRoles/ClaimedRole", 'l'))
    signer_roles_certified = SweetXml.xpath(xml_document, SweetXml.sigil_x("#{base}/SignerRole/CertifiedRoles/CertifiedRole", 'l'))

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
    put_signing_time(signature_properties, signing_time)
  end

  def put_signing_time(signed_signature_properties, signing_time) do
    xml = XmlBuilder.element("SigningTime", [
      signing_time
    ])
    Map.put(signed_signature_properties, :signing_time, xml)
  end


  def put_x590_certificate(signed_signature_properties, nil), do: Map.put(signed_signature_properties, :signing_certificate, nil)
  def put_x590_certificate(signed_signature_properties, %{issuer: issuer, serial: serial, digest_type: digest_type, digest: digest}) do
    put_x590_certificate(signed_signature_properties, issuer, serial, digest_type, digest)
  end
  def put_x590_certificate(signed_signature_properties, map) when is_map(map) do
    values = %{
      issuer: nil,
      serial: nil,
      digest_type: nil,
      digest: nil
    }
    |> Map.merge(map)

    put_x590_certificate(signed_signature_properties, values)
  end

  def put_x590_certificate(signed_signature_properties, issuer, serial, digest_type, digest) do

    xml = XmlBuilder.element("SigningCertificate", [
      XmlBuilder.element("Cert", [
        XmlBuilder.element("CertDigest", [
          XmlBuilder.element("DigestMethod", %{"Algorithm" => HashMethods.get_w3_url(digest_type)}),
          XmlBuilder.element("DigestValue", [
            digest
          ])
        ]),
        XmlBuilder.element("IssuerSerial", [
          XmlBuilder.element("X509IssuerName", [
            issuer
          ]),
          XmlBuilder.element("X509SerialNumber", [
            serial
          ])
        ])
      ])
    ])

    Map.put(signed_signature_properties, :signing_certificate, xml)
  end


  def put_signature_production_place(signature_properties, nil), do: Map.put(signature_properties, :signature_production_place, nil)
  def put_signature_production_place(signature_properties, %{city_name: city_name, country: country}) do
    put_signature_production_place(signature_properties, city_name, country)
  end
  def put_signature_production_place(signature_properties, map) when is_map(map) do
    values = %{
      city_name: nil,
      country: nil
    }
    |> Map.merge(map)

    put_signature_production_place(signature_properties, values)
  end
  @doc """
  puts the signature production place in the signed signature properties
  """
  def put_signature_production_place(signed_signature_properties, city_name, country) do
    xml = XmlBuilder.element("SignatureProductionPlace", [
      XmlBuilder.element("City", [
        city_name
      ]),
      XmlBuilder.element("CountryName", [
        country
      ])
    ])

    Map.put(signed_signature_properties, :signature_production_place, xml)

  end

  @doc """
  puts the signer role in the signed signature properties
  """
  def put_signer_role(signed_signature_properties, nil), do: Map.put(signed_signature_properties, :signer_role, nil)
  def put_signer_role(signed_signature_properties, %{claimed_roles: claimed_roles, certified_roles: certified_roles}) do
    put_signer_role(signed_signature_properties, claimed_roles, certified_roles)
  end
  def put_signer_role(signed_signature_properties, map) when is_map(map) do
    values = %{
      claimed_roles: [],
      certified_roles: []
    }
    |> Map.merge(map)
    put_signer_role(signed_signature_properties, values)
  end
  def put_signer_role(signed_signature_properties, claimed_roles, certified_roles) do

    xml = XmlBuilder.element("SignerRole", [
      XmlBuilder.element("ClaimedRoles", [
        Enum.map(claimed_roles, fn role -> XmlBuilder.element("ClaimedRole", [role]) end)
      ]),
      XmlBuilder.element("CertifiedRoles", [
        Enum.map(certified_roles, fn role -> XmlBuilder.element("CertifiedRole", [role]) end)
      ])
    ])

    Map.put(signed_signature_properties, :signer_role, xml)

  end

  def build(nil), do: build(new())

  def build(signed_signature_properties) do



    xml = XmlBuilder.element("SignedSignatureProperties", [
      signed_signature_properties.signing_time,
      signed_signature_properties.signing_certificate,
      signed_signature_properties.signature_policy_identifier,
      signed_signature_properties.signature_production_place,
      signed_signature_properties.signer_role
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
