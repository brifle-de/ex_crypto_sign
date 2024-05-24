defmodule ExCryptoSign.Constants.SignatureMethods do


  alias ExCryptoSign.Constants.HashMethods


  @rsa_sha1 "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
  @rsa_sha256 "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
  @rsa_sha512 "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
  @rsa_sha384 "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
  @rsa_md5 "http://www.w3.org/2001/04/xmldsig-more#rsa-md5"
  @rsa_sha3_256 "http://www.w3.org/2007/05/xmldsig-more#rsa-sha3-256"
  @rsa_sha3_512 "http://www.w3.org/2007/05/xmldsig-more#rsa-sha3-512"
  @rsa_sha3_384 "http://www.w3.org/2007/05/xmldsig-more#rsa-sha3-384"
  @ecdsa_sha1 "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1"
  @ecdsa_sha256 "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
  @ecdsa_sha512 "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"
  @ecdsa_sha384 "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
  @ecdsa_sha3_256 "http://www.w3.org/2007/05/xmldsig-more#ecdsa-sha3-256"
  @ecdsa_sha3_512 "http://www.w3.org/2007/05/xmldsig-more#ecdsa-sha3-512"
  @ecdsa_sha3_384 "http://www.w3.org/2007/05/xmldsig-more#ecdsa-sha3-384"


  def rsa_sha1 do
    @rsa_sha1
  end

  def rsa_sha256 do
    @rsa_sha256
  end


  def rsa_sha512 do
    @rsa_sha512
  end

  def rsa_sha384 do
    @rsa_sha384
  end

  def rsa_md5 do
    @rsa_md5
  end

  def rsa_sha3_256 do
    @rsa_sha3_256
  end

  def rsa_sha3_512 do
    @rsa_sha3_512
  end

  def rsa_sha3_384 do
    @rsa_sha3_384
  end


  def ecdsa_sha1 do
    @ecdsa_sha1
  end

  def ecdsa_sha256 do
    @ecdsa_sha256
  end

  def ecdsa_sha512 do
    @ecdsa_sha512
  end

  def ecdsa_sha384 do
    @ecdsa_sha384
  end

  def ecdsa_sha3_256 do
    @ecdsa_sha3_256
  end

  def ecdsa_sha3_512 do
    @ecdsa_sha3_512
  end


  def ecdsa_sha3_384 do
    @ecdsa_sha3_384
  end

  @doc """
  gets the w3 url for the signature method. If an illegal signature method is passed, it returns "unknown signature method"
  """
  def get_w3_url(method_atom) do

    case method_atom do
      :rsa_sha1 -> rsa_sha1()
      :rsa_sha256 -> rsa_sha256()
      :rsa_sha512 -> rsa_sha512()
      :rsa_sha384 -> rsa_sha384()
      :rsa_md5 -> rsa_md5()
      :rsa_sha3_256 -> rsa_sha3_256()
      :rsa_sha3_512 -> rsa_sha3_512()
      :rsa_sha3_384 -> rsa_sha3_384()
      :ecdsa_sha1 -> ecdsa_sha1()
      :ecdsa_sha256 -> ecdsa_sha256()
      :ecdsa_sha512 -> ecdsa_sha512()
      :ecdsa_sha384 -> ecdsa_sha384()
      :ecdsa_sha3_256 -> ecdsa_sha3_256()
      :ecdsa_sha3_512 -> ecdsa_sha3_512()
      :ecdsa_sha3_384 -> ecdsa_sha3_384()
      _ -> "unknown signature method"
    end

  end

  def from_w3_url(url) do
    case url do
      @rsa_sha1 -> :rsa_sha1
      @rsa_sha256 -> :rsa_sha256
      @rsa_sha512 -> :rsa_sha512
      @rsa_sha384 -> :rsa_sha384
      @rsa_md5 -> :rsa_md5
      @rsa_sha3_256 -> :rsa_sha3_256
      @rsa_sha3_512 -> :rsa_sha3_512
      @rsa_sha3_384 -> :rsa_sha3_384
      @ecdsa_sha1 -> :ecdsa_sha1
      @ecdsa_sha256 -> :ecdsa_sha256
      @ecdsa_sha512 -> :ecdsa_sha512
      @ecdsa_sha384 -> :ecdsa_sha384
      @ecdsa_sha3_256 -> :ecdsa_sha3_256
      @ecdsa_sha3_512 -> :ecdsa_sha3_512
      @ecdsa_sha3_384 -> :ecdsa_sha3_384
      _ -> "unknown signature method"
    end
  end

  def get_digest_method(method) do
    case method do
      :rsa_sha1 -> HashMethods.sha1()
      :rsa_sha256 -> HashMethods.sha256()
      :rsa_sha512 -> HashMethods.sha512()
      :rsa_sha384 -> HashMethods.sha384()
      :rsa_md5 -> HashMethods.md5()
      :rsa_sha3_256 -> HashMethods.sha3_256()
      :rsa_sha3_512 -> HashMethods.sha3_512()
      :rsa_sha3_384 -> HashMethods.sha3_384()
      :ecdsa_sha1 -> HashMethods.sha1()
      :ecdsa_sha256 -> HashMethods.sha256()
      :ecdsa_sha512 -> HashMethods.sha512()
      :ecdsa_sha384 -> HashMethods.sha384()
      :ecdsa_sha3_256 -> HashMethods.sha3_256()
      :ecdsa_sha3_512 -> HashMethods.sha3_512()
      :ecdsa_sha3_384 -> HashMethods.sha3_384()
      _ -> "unknown signature method"
    end |> HashMethods.from_w3_url()
  end

  @spec get_signature_method(any) :: :ecdsa | :rsa | <<_::192>>
  def get_signature_method(method) do
    case method do
      :rsa_sha1 -> :rsa
      :rsa_sha256 -> :rsa
      :rsa_sha512 -> :rsa
      :rsa_sha384 -> :rsa
      :rsa_md5 -> :rsa
      :rsa_sha3_256 -> :rsa
      :rsa_sha3_512 -> :rsa
      :rsa_sha3_384 -> :rsa
      :ecdsa_sha1 -> :ecdsa
      :ecdsa_sha256 -> :ecdsa
      :ecdsa_sha512 -> :ecdsa
      :ecdsa_sha384 -> :ecdsa
      :ecdsa_sha3_256 -> :ecdsa
      :ecdsa_sha3_512 -> :ecdsa
      :ecdsa_sha3_384 -> :ecdsa
      _ -> "unknown signature method"
    end
  end

end
