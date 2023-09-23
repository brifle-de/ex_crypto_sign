defmodule ExCryptoSign.Properties.UnsignedSignatureProperties do

  alias ExCryptoSign.Constants.HashMethods

  def new() do
    %{
      signature_time_stamps: nil,
      complete_certificate_refs: nil,
      complete_revocation_refs: nil,
      sig_and_ref_time_stamps: nil,
      archive_time_stamps: nil,
      certificate_values: nil,
      revocation_values: nil,
      counter_signatures: nil,
    }
  end

  def new(map) when is_map(map) do
    new()
    |> put_signature_time_stamps(Map.get(map, :signature_time_stamps))
    |> put_complete_certificate_refs(Map.get(map, :complete_certificate_refs))
    |> put_complete_revocation_refs(Map.get(map, :complete_revocation_refs))
    |> put_sig_and_ref_time_stamps(Map.get(map, :sig_and_ref_time_stamps))
    |> put_archive_time_stamps(Map.get(map, :archive_time_stamps))
    |> put_certificate_values(Map.get(map, :certificate_values))
    |> put_revocation_values(Map.get(map, :revocation_values))
    |> put_counter_signatures(Map.get(map, :counter_signatures))
  end

  def parse_document(xml_document) do
    base = "//ds:Signature/ds:Object/ds:QualifyingProperties/ds:UnsignedProperties/ds:UnsignedSignatureProperties"
    signature_time_stamps = SweetXml.xpath(xml_document, SweetXml.sigil_x("#{base}/ds:SignatureTimeStamp"))
    complete_certificate_refs = SweetXml.xpath(xml_document, SweetXml.sigil_x("#{base}/ds:CompleteCertificateRefs"))
    complete_revocation_refs = SweetXml.xpath(xml_document, SweetXml.sigil_x("#{base}/ds:CompleteRevocationRefs"))
    sig_and_ref_time_stamps = SweetXml.xpath(xml_document, SweetXml.sigil_x("#{base}/ds:SigAndRefsTimeStamp"))
    archive_time_stamps = SweetXml.xpath(xml_document, SweetXml.sigil_x("#{base}/ds:ArchiveTimeStamp"))
    certificate_values = SweetXml.xpath(xml_document, SweetXml.sigil_x("#{base}/ds:CertificateValues"))
    revocation_values = SweetXml.xpath(xml_document, SweetXml.sigil_x("#{base}/ds:RevocationValues"))
    counter_signatures = SweetXml.xpath(xml_document, SweetXml.sigil_x("#{base}/ds:CounterSignature"))


    %{
      signature_time_stamps: signature_time_stamps,
      complete_certificate_refs: complete_certificate_refs,
      complete_revocation_refs: complete_revocation_refs,
      sig_and_ref_time_stamps: sig_and_ref_time_stamps,
      archive_time_stamps: archive_time_stamps,
      certificate_values: certificate_values,
      revocation_values: revocation_values,
      counter_signatures: counter_signatures,
    }

  end

  def put_signature_time_stamps(unsigned_signature_properties, nil), do: Map.put(unsigned_signature_properties, :signature_time_stamps, nil)
  def put_signature_time_stamps(unsigned_signature_properties, %{time_stamp: time_stamp}) do
    put_signature_time_stamps(unsigned_signature_properties, time_stamp)
  end
  def put_signature_time_stamp(unsigned_signature_properties, time_stamp) do
    xml = XmlBuilder.element("SignatureTimeStamp", [
      XmlBuilder.element("EncapsulatedTimeStamp", [
        time_stamp
      ])
    ])
    Map.put(unsigned_signature_properties, :signature_time_stamps, xml)
  end

  def put_complete_certificate_refs(unsigned_signature_properties, nil), do: Map.put(unsigned_signature_properties, :complete_certificate_refs, nil)
  def put_complete_certificate_refs(unsigned_signature_properties, %{digest_method: digest_method, digest_value: digest_value, issuer_name: issuer_name, serial_number: serial_number}) do
    put_complete_certificate_refs(unsigned_signature_properties, digest_method, digest_value, issuer_name, serial_number)
  end
  def put_complete_certificate_refs(unsigned_signature_properties, digest_method, digest_value, issuer_name, serial_number) do
    xml = XmlBuilder.element("CompleteCertificateRefs", [
      XmlBuilder.element("CertRefs", [
        XmlBuilder.element("Cert", [
          XmlBuilder.element("CertDigest", [
            XmlBuilder.element("DigestMethod", %{"Algorithm" => HashMethods.get_w3_url(digest_method)}),
            XmlBuilder.element("DigestValue", [
              digest_value
            ])
          ]),
          XmlBuilder.element("IssuerSerial", [
            XmlBuilder.element("X509IssuerName", [
              issuer_name
            ]),
            XmlBuilder.element("X509SerialNumber", [
              serial_number
            ])
          ])
        ])
      ])
    ])
    Map.put(unsigned_signature_properties, :complete_certificate_refs, xml)
  end

  @doc """
  puts the complete revocation refs in the unsigned signature properties
  """
  def put_complete_revocation_refs(unsigned_signature_properties, nil), do: Map.put(unsigned_signature_properties, :complete_revocation_refs, nil)
  def put_complete_revocation_refs(unsigned_signature_properties, %{crls_refs: crls_refs, ocsp_refs: ocsp_refs, other_refs: other_refs}) do
    put_complete_revocation_refs(unsigned_signature_properties, crls_refs, ocsp_refs, other_refs)
  end
  def put_complete_revocation_refs(unsigned_signature_properties, crls_refs, ocsp_refs, other_refs, id \\ nil) do

    attr = if id == nil do
      %{}
    else
      %{"Id" => id}
    end

    xml = XmlBuilder.element("CompleteRevocationRefs", attr, [
      XmlBuilder.element("CRLRefs", [
        crls_refs
      ]),
      XmlBuilder.element("OCSPRefs", [
        ocsp_refs
      ]),
      XmlBuilder.element("OtherRefs", [
        other_refs
      ])
    ])

    Map.put(unsigned_signature_properties, :complete_revocation_refs, xml)
  end

  def put_sig_and_ref_time_stamps(unsigned_signature_properties, nil), do: Map.put(unsigned_signature_properties, :sig_and_ref_time_stamps, nil)
  def put_sig_and_ref_time_stamps(unsigned_signature_properties, %{time_stamp: time_stamp}) do
    put_sig_and_ref_time_stamps(unsigned_signature_properties, time_stamp)
  end
  def put_sig_and_ref_time_stamps(unsigned_signature_properties, time_stamp) do
    xml = XmlBuilder.element("SigAndRefsTimeStamp", [
      XmlBuilder.element("EncapsulatedTimeStamp", [
        time_stamp
      ])
    ])
    Map.put(unsigned_signature_properties, :sig_and_ref_time_stamps, xml)
  end

  def put_archive_time_stamps(unsigned_signature_properties, nil), do: Map.put(unsigned_signature_properties, :archive_time_stamps, nil)
  def put_archive_time_stamps(unsigned_signature_properties, %{time_stamp: time_stamp}) do
    put_archive_time_stamps(unsigned_signature_properties, time_stamp)
  end
  def put_archive_time_stamps(unsigned_signature_properties, time_stamp) do
    xml = XmlBuilder.element("ArchiveTimeStamp", [
      XmlBuilder.element("EncapsulatedTimeStamp", [
        time_stamp
      ])
    ])
    Map.put(unsigned_signature_properties, :archive_time_stamps, xml)
  end

  def put_certificate_values(unsigned_signature_properties, nil), do: Map.put(unsigned_signature_properties, :certificate_values, nil)
  def put_certificate_values(unsigned_signature_properties, %{certificate_values: certificate_values}) do
    put_certificate_values(unsigned_signature_properties,certificate_values)
  end
  def put_certificate_values(unsigned_signature_properties, certificate_values) do
    xml = XmlBuilder.element("CertificateValues", [
      certificate_values
    ])
    Map.put(unsigned_signature_properties, :certificate_values, xml)
  end

  def put_revocation_values(unsigned_signature_properties, nil), do: Map.put(unsigned_signature_properties, :revocation_values, nil)
  def put_revocation_values(unsigned_signature_properties, %{revocation_values: revocation_values, }) do
    put_revocation_values(unsigned_signature_properties, revocation_values)
  end
  def put_revocation_values(unsigned_signature_properties, revocation_values) do
    xml = XmlBuilder.element("RevocationValues", [
      revocation_values
    ])
    Map.put(unsigned_signature_properties, :revocation_values, xml)
  end

  def put_counter_signatures(unsigned_signature_properties, nil), do: Map.put(unsigned_signature_properties, :counter_signatures, nil)
  def put_counter_signatures(unsigned_signature_properties, %{counter_signatures: counter_signatures}) do
    put_counter_signatures(unsigned_signature_properties, counter_signatures)
  end
  def put_counter_signatures(unsigned_signature_properties, counter_signatures) do
    xml = XmlBuilder.element("CounterSignature", [
      counter_signatures
    ])
    Map.put(unsigned_signature_properties, :counter_signatures, xml)
  end

  def build(nil), do: build(new())

  def build(unsigned_signature_properties) do
    xml = XmlBuilder.element("UnsignedSignatureProperties", [
      unsigned_signature_properties.signature_time_stamps,
      unsigned_signature_properties.complete_certificate_refs,
      unsigned_signature_properties.complete_revocation_refs,
      unsigned_signature_properties.sig_and_ref_time_stamps,
      unsigned_signature_properties.archive_time_stamps,
      unsigned_signature_properties.certificate_values,
      unsigned_signature_properties.revocation_values,
      unsigned_signature_properties.counter_signatures
    ]
      |> Enum.filter(fn x -> x != nil end)
      |> Enum.filter(fn x -> x != [] end)
    )
    xml
  end

  def build_xml(unsigned_signature_properties), do: build(unsigned_signature_properties) |> XmlBuilder.generate()



end
