defmodule ExCryptoSignTest do
  use ExUnit.Case
  doctest ExCryptoSign

  test "create and verify signature" do

    # generate a key pair
    {key_pem, cert_pem} = Support.CertCreator.generate_dummy_cert()

    docs = [%{content: "document1", id: "2341ac23HAbcA"}, %{content: "document2", id: "671ac23HAbcA"}]
    city_name = "Stuttgart"
    signing_time = DateTime.now!("Etc/UTC") |> DateTime.add(3600, :second) |> DateTime.to_string

    xml = generate_xml_document(docs, city_name, signing_time, cert_pem)

    {:ok, {doc_correct, sign}} = ExCryptoSign.Util.Signer.sign(xml, key_pem)

    assert ExCryptoSign.Util.Verifier.verifies_document(doc_correct, docs)

    # simulate signing by other party
    opts = get_ops(docs, city_name, signing_time, cert_pem)
    {:ok, {_doc, signature_new}} = ExCryptoSign.Util.Signer.sign(xml, key_pem)

    res = ExCryptoSign.sign_and_verify("signature_id", docs, cert_pem, signature_new, opts)

    assert {:ok, signed_xml} = res

    File.write!("test/files/test-create.xml", signed_xml)
    assert ExCryptoSign.Util.Verifier.verifies_document(signed_xml, docs)

  end


  test "create and verify long signature (2MB in less than 1s)" do

    # generate a key pair
    {key_pem, cert_pem} = Support.CertCreator.generate_dummy_cert()


    # get current time in UTC
    start_time = DateTime.utc_now()

    content = String.duplicate("a", 2000000)

    docs = [%{content: content, id: "671ac23HAbcA"}]
    city_name = "Stuttgart"
    signing_time = DateTime.now!("Etc/UTC") |> DateTime.add(3600, :second) |> DateTime.to_string

    xml = generate_xml_document(docs, city_name, signing_time, cert_pem)

    {:ok, {doc_correct, sign}} = ExCryptoSign.Util.Signer.sign(xml, key_pem)

    # get current time in UTC
    end_time = DateTime.utc_now()

    # get the difference in milliseconds
    duration = DateTime.diff(end_time, start_time, :millisecond)
    assert duration < 1000

    assert ExCryptoSign.Util.Verifier.verifies_document(doc_correct, docs)

    # simulate signing by other party
    opts = get_ops(docs, city_name, signing_time, cert_pem)
    {:ok, {_doc, signature_new}} = ExCryptoSign.Util.Signer.sign(xml, key_pem)

    res = ExCryptoSign.sign_and_verify("signature_id", docs, cert_pem, signature_new, opts)

    assert {:ok, signed_xml} = res

    File.write!("test/files/test-create.xml", signed_xml)
    assert ExCryptoSign.Util.Verifier.verifies_document(signed_xml, docs)

  end

  test "wrong signature" do



    # generate a key pair
    {key_pem, cert_pem} = Support.CertCreator.generate_dummy_cert()
    {key_pem2, _cert_pem2} = Support.CertCreator.generate_dummy_cert()

    docs = [%{content: "document1", id: "2341ac23HAbcA"}, %{content: "document2", id: "671ac23HAbcA"}]
    city_name = "Stuttgart"
    signing_time = DateTime.now!("Etc/UTC") |> DateTime.add(3600, :second) |> DateTime.to_string

    xml = generate_xml_document(docs, city_name, signing_time, cert_pem)

    {:ok, {doc_correct, sign}} = ExCryptoSign.Util.Signer.sign(xml, key_pem)

    assert ExCryptoSign.Util.Verifier.verifies_document(doc_correct, docs)

    # simulate signing by other party
    opts = get_ops(docs, city_name, signing_time, cert_pem)
    {:ok, {_doc, signature_new}} = ExCryptoSign.Util.Signer.sign(xml, key_pem2)

    res = ExCryptoSign.sign_and_verify("signature_id", docs, cert_pem, signature_new, opts)

    assert {:error, :signature} = res

  end

  test "wrong documents" do

    # generate a key pair
    {key_pem, cert_pem} = Support.CertCreator.generate_dummy_cert()
    {key_pem2, _cert_pem2} = Support.CertCreator.generate_dummy_cert()

    docs = [%{content: "document1", id: "2341ac23HAbcA"}, %{content: "document2", id: "671ac23HAbcA"}]
    docs_wrong = [%{content: "document55551", id: "2341ac23HAbcA"}, %{content: "document99992", id: "671ac23HAbcA"}]
    city_name = "Stuttgart"
    signing_time = DateTime.now!("Etc/UTC") |> DateTime.add(3600, :second) |> DateTime.to_string

    xml = generate_xml_document(docs, city_name, signing_time, cert_pem)




    {:ok, {doc_correct, sign}} = ExCryptoSign.Util.Signer.sign(xml, key_pem)


    assert ExCryptoSign.Util.Verifier.verifies_document(doc_correct, docs)

    # simulate signing by other party
    opts = get_ops(docs_wrong, city_name, signing_time, cert_pem)
    {:ok, {_doc, signature_new}} = ExCryptoSign.Util.Signer.sign(xml, key_pem2)

    res = ExCryptoSign.sign_and_verify("signature_id", docs_wrong, cert_pem, signature_new, opts)

    assert {:error, :signature} = res


  end

  test "get document ids" do
      # generate a key pair
      {key_pem, cert_pem} = Support.CertCreator.generate_dummy_cert()

      docs = [%{content: "document1", id: "2341ac23HAbcA"}, %{content: "document2", id: "671ac23HAbcA"}]
      city_name = "Stuttgart"
      signing_time = DateTime.now!("Etc/UTC") |> DateTime.add(3600, :second) |> DateTime.to_string

      xml = generate_xml_document(docs, city_name, signing_time, cert_pem)



      {:ok, {doc_correct, sign}} = ExCryptoSign.Util.Signer.sign(xml, key_pem)

      assert ExCryptoSign.Util.Verifier.verifies_document(doc_correct, docs)

      # simulate signing by other party
      opts = get_ops(docs, city_name, signing_time, cert_pem)
      {:ok, {_doc, signature_new}} = ExCryptoSign.Util.Signer.sign(xml, key_pem)

      res = ExCryptoSign.sign_and_verify("signature_id", docs, cert_pem, signature_new, opts)

      assert {:ok, signed_xml} = res

      assert ExCryptoSign.Util.Verifier.verifies_document(signed_xml, docs)

      assert ["#data-2341ac23HAbcA", "#data-671ac23HAbcA"] == ExCryptoSign.get_document_ids(signed_xml)


  end

  test "export" do
       # generate a key pair
       {key_pem, cert_pem} = Support.CertCreator.generate_dummy_cert()

       docs = [%{content: "document1", id: "2341ac23HAbcA"}, %{content: "document2", id: "671ac23HAbcA"}]
       city_name = "Stuttgart"
       signing_time = DateTime.now!("Etc/UTC") |> DateTime.add(3600, :second) |> DateTime.to_string

       xml = generate_xml_document(docs, city_name, signing_time, cert_pem)



       {:ok, {doc_correct, sign}} = ExCryptoSign.Util.Signer.sign(xml, key_pem)

       assert ExCryptoSign.Util.Verifier.verifies_document(doc_correct, docs)

       # simulate signing by other party
       opts = get_ops(docs, city_name, signing_time, cert_pem)
       {:ok, {_doc, signature_new}} = ExCryptoSign.Util.Signer.sign(xml, key_pem)

       res = ExCryptoSign.sign_and_verify("signature_id", docs, cert_pem, signature_new, opts)

       assert {:ok, signed_xml} = res

       assert ExCryptoSign.Util.Verifier.verifies_document(signed_xml, docs)

       assert ["#data-2341ac23HAbcA", "#data-671ac23HAbcA"] == ExCryptoSign.get_document_ids(signed_xml)

       export_data = %{"https://documents.brifle.de/2341ac23HAbcA" => "document1", "https://documents.brifle.de/671ac23HAbcA" => "document2"}

       export = ExCryptoSign.export_document_signatures(signed_xml, export_data)



       File.write!("test/files/test-export.xml", export)


  end

  defp get_ops(documents, city_name, signing_time, cert_pem) do
    docs_opts = [
      signature_properties: %{
        signing_time: signing_time,
        signing_certificate: %{
          issuer: ExCryptoSign.Util.PemCertificate.get_certificate_issuer(cert_pem),
          serial: ExCryptoSign.Util.PemCertificate.get_certificate_serial(cert_pem),
          digest_type: :sha256,
          digest: ExCryptoSign.Util.PemCertificate.get_certificate_digest(cert_pem, :sha256)
        },
        signature_production_place: %{
          city_name: city_name,
          country: "Germany"
        },
        signer_role: %{
          claimed_roles: ["role with ä", "role2"]
        }
      },
      signed_data_object_properties: %{
        data_object_format: [
          %{
          mime_type: "text/xml",
          encoding: "UTF-8",
          description: "Die Beschreibung",
          object_reference: "#doc-1"
        },
          %{
          mime_type: "text/xml",
          encoding: "UTF-8",
          description: "Die Beschreibung",
          object_reference: "#doc-2"
        }
      ]
      },
      unsigned_signature_properties: %{

      },
      # hash_algorithm: :sha256
    ]
  end

  def generate_xml_document(documents, city_name, signing_time, pem_cert) do
    opts = get_ops(documents, city_name, signing_time, pem_cert)

    # prepare document for signing

    signature_document = ExCryptoSign.prepare_document("signature_id",documents, pem_cert, opts)
    signature_document
  end




end
