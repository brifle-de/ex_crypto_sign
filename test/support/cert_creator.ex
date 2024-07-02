defmodule Support.CertCreator do

  @ca_key "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIJjL6EO8W8LfdIe+dC9ewMNcOvRNGIyhwaIeHh00GmoAoAoGCCqGSM49\nAwEHoUQDQgAEcgP4FbahIwB022cg4GGJs9fFUCFY3EpW3c4XMMM+yiy4f90bZpnb\nBXvP7yVv/Ui9sYs+bbh+FmUSdJ8/M2clYw==\n-----END EC PRIVATE KEY-----\n\n"
  @ca_cert "-----BEGIN CERTIFICATE-----\nMIICDTCCAbSgAwIBAgIIZV6AfxPz0JkwCgYIKoZIzj0EAwIwWTELMAkGA1UEBhMC\nVVMxCzAJBgNVBAgMAkNBMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMQ0wCwYDVQQK\nDARBY21lMRYwFAYDVQQDDA1FQ0RTQSBSb290IENBMB4XDTI0MDUyNDE3MjUzMloX\nDTQ5MDUyNDE3MzAzMlowWTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRYwFAYD\nVQQHDA1TYW4gRnJhbmNpc2NvMQ0wCwYDVQQKDARBY21lMRYwFAYDVQQDDA1FQ0RT\nQSBSb290IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcgP4FbahIwB022cg\n4GGJs9fFUCFY3EpW3c4XMMM+yiy4f90bZpnbBXvP7yVv/Ui9sYs+bbh+FmUSdJ8/\nM2clY6NmMGQwEgYDVR0TAQH/BAgwBgEB/wIBATAOBgNVHQ8BAf8EBAMCAYYwHQYD\nVR0OBBYEFGw4dP0/n4MVkSwlZkHWOKXz3Ml7MB8GA1UdIwQYMBaAFGw4dP0/n4MV\nkSwlZkHWOKXz3Ml7MAoGCCqGSM49BAMCA0cAMEQCIFZ1BPiAGPrhW0gFOdZV2cBA\naoo4nyvRFUHDqDWMqTWDAiB3jIS4h2hA6GfmQyvddG6RqXvi9GpgGQzJ0BoUF78E\nlw==\n-----END CERTIFICATE-----\n\n"


  def generate_dummy_cert() do
    ca_key = X509.PrivateKey.from_pem!(@ca_key)
    ca = X509.Certificate.from_pem!(@ca_cert)


    my_key = X509.PrivateKey.new_ec(:secp256r1)
    my_cert = my_key |>

    X509.PublicKey.derive()
    |> X509.Certificate.new(
      "/C=US/ST=CA/L=San Francisco/O=Acme/CN=Sample",
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
    ca = X509.Certificate.self_signed(ca_key,"/C=US/ST=CA/L=San Francisco/O=Acme/CN=ECDSA Root CA", template: :root_ca)

    {ca_key, ca}
  end


  def private_key_from_pem(pem) do
    X509.PrivateKey.from_pem(pem)
  end
end
