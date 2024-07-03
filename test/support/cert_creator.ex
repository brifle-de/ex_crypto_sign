defmodule Support.CertCreator do

  @ca_key "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIP1M6KFzK0kGpYxWdOAaRAyTl0KI03xmbOZNsodRRkuhoAoGCCqGSM49\nAwEHoUQDQgAERceuXj8HQ27w8IA+JKIhYNOi+S3Ks3SLhlxFYxUuRsRHLStN2f5t\n/Dt4MiXEbFi5izZi/CVYbWeaLXqRvv2wiA==\n-----END EC PRIVATE KEY-----\n\n"
  @ca_cert "-----BEGIN CERTIFICATE-----\nMIICIjCCAcigAwIBAgIILnSWXkiUiygwCgYIKoZIzj0EAwIwYzELMAkGA1UEBhMC\nREUxCzAJBgNVBAgMAkJXMRIwEAYDVQQHDAlTdHV0dGdhcnQxDzANBgNVBAoMBkJy\naWZsZTEiMCAGA1UEAwwZRUNEU0EgQnJpZmxlIFRlc3QgUm9vdCBDQTAeFw0yNDA3\nMDMyMDAwMTFaFw00OTA3MDMyMDA1MTFaMGMxCzAJBgNVBAYTAkRFMQswCQYDVQQI\nDAJCVzESMBAGA1UEBwwJU3R1dHRnYXJ0MQ8wDQYDVQQKDAZCcmlmbGUxIjAgBgNV\nBAMMGUVDRFNBIEJyaWZsZSBUZXN0IFJvb3QgQ0EwWTATBgcqhkjOPQIBBggqhkjO\nPQMBBwNCAARFx65ePwdDbvDwgD4koiFg06L5LcqzdIuGXEVjFS5GxEctK03Z/m38\nO3gyJcRsWLmLNmL8JVhtZ5otepG+/bCIo2YwZDASBgNVHRMBAf8ECDAGAQH/AgEB\nMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUT6SZIOOzGgMvKRYivNwhXj5c5HMw\nHwYDVR0jBBgwFoAUT6SZIOOzGgMvKRYivNwhXj5c5HMwCgYIKoZIzj0EAwIDSAAw\nRQIhAMfUPrHUaKxmBZnexxg0vyTNyUWhr48vssXT/I8bl/RdAiAyiX5MVoYF5UWT\naNjsfCUt5WfTlYYmEt19BcD+yzQGkA==\n-----END CERTIFICATE-----\n\n"



  def generate_dummy_cert(curve \\ :secp256r1) do
    ca_key = X509.PrivateKey.from_pem!(@ca_key)
    ca = X509.Certificate.from_pem!(@ca_cert)


    my_key = X509.PrivateKey.new_ec(curve)
    my_cert = my_key |>

    X509.PublicKey.derive()
    |> X509.Certificate.new(
      "/C=DE/ST=BW/L=Stuttgart/O=Brifle/CN=Brifle Test",
      ca, ca_key,
      extensions: [
        subject_alt_name: X509.Certificate.Extension.subject_alt_name(["example.org", "www.example.org"])
      ]
    )

    pem_key = X509.PrivateKey.to_pem(my_key)
    pem_cert = X509.Certificate.to_pem(my_cert)

    {pem_key, pem_cert}
  end

  def generate_certifcate_from_ca({ca_key, ca}, subject) do
    my_key =  X509.PrivateKey.new_ec(:secp384r1)
    my_cert = my_key |>
    X509.PublicKey.derive()
    |> X509.Certificate.new(
      subject,
      ca, ca_key,
      extensions: [
        subject_alt_name: X509.Certificate.Extension.subject_alt_name(["example.org", "www.example.org"])
      ]
    )

    pem_key = X509.PrivateKey.to_pem(my_key)
    pem_cert = X509.Certificate.to_pem(my_cert)

    {pem_key, pem_cert}
  end

  def generate_ca() do
    ca_key = X509.PrivateKey.new_ec(:secp256r1)
    ca = X509.Certificate.self_signed(ca_key,"/C=DE/ST=BW/L=Stuttgart/O=Brifle/CN=ECDSA Brifle Test Root CA", template: :root_ca)

    {ca_key, ca}
  end


  def private_key_from_pem(pem) do
    X509.PrivateKey.from_pem(pem)
  end
end
