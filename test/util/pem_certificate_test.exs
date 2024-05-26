defmodule Util.PemCertificateTest do
  alias ExCryptoSign.Util.PemCertificate

  use ExUnit.Case

  test "verify valid chain" do
    {ca_key, ca_cert} = Support.CertCreator.generate_ca()
    {key_pem, cert_pem} = Support.CertCreator.generate_certifcate_from_ca({ca_key, ca_cert}, "/C=US/ST=CA/L=San Francisco/O=Acme/CN=Sample")
    ca_pem = ca_cert |> X509.Certificate.to_pem()

    assert {:ok, res } = PemCertificate.validate_certificate_chain(ca_pem, cert_pem)


  end

  test "invalid chain" do
    {ca_key, ca_cert} = Support.CertCreator.generate_ca()
    {ca_key2, ca_cert2} = Support.CertCreator.generate_ca()
    {key_pem, cert_pem} = Support.CertCreator.generate_certifcate_from_ca({ca_key, ca_cert}, "/C=US/ST=CA/L=San Francisco/O=Acme/CN=Sample")
    ca_pem = ca_cert |> X509.Certificate.to_pem()
    ca_pem2 = ca_cert2 |> X509.Certificate.to_pem()

    assert {:error, :invalid_signature} = PemCertificate.validate_certificate_chain(ca_pem2, cert_pem)


  end
end
