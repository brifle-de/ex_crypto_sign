defmodule ExCryptoSign.Constants.HashMethods do


  @sha1 "http://www.w3.org/2000/09/xmldsig#sha1"
  @sha256 "http://www.w3.org/2001/04/xmlenc#sha256"
  @sha512 "http://www.w3.org/2001/04/xmlenc#sha512"
  @sha384 "http://www.w3.org/2001/04/xmldsig-more#sha384"
  @md5 "http://www.w3.org/2001/04/xmldsig-more#md5"
  @sha3_256 "http://www.w3.org/2007/05/xmldsig-more#sha3-256"
  @sha3_512 "http://www.w3.org/2007/05/xmldsig-more#sha3-512"
  @sha3_384 "http://www.w3.org/2007/05/xmldsig-more#sha3-384"


  def sha1 do
    @sha1
  end

  def sha256 do
    @sha256
  end

  def sha512 do
    @sha512
  end

  def sha384 do
    @sha384
  end

  def md5 do
    @md5
  end

  def sha3_256 do
    @sha3_256
  end

  def sha3_512 do
    @sha3_512
  end

  def sha3_384 do
    @sha3_384
  end




  @doc """
  gets the w3 url for the hash method. If an illegal hash method is passed, it returns "unknown hash method"
  """
  def get_w3_url(sha_atom) do
    case sha_atom do
      :sha1 -> sha1()
      :sha256 -> sha256()
      :sha512 -> sha512()
      :sha384 -> sha384()
      :md5 -> md5()
      :sha3_256 -> sha3_256()
      :sha3_512 -> sha3_512()
      :sha3_384 -> sha3_384()
      _ -> "unknown hash method"
    end
  end

  def from_w3_url(url) do
    case url do
      @sha1 -> :sha1
      @sha256 -> :sha256
      @sha512 -> :sha512
      @sha384 -> :sha384
      @md5 -> :md5
      @sha3_256 -> :sha3_256
      @sha3_512 -> :sha3_512
      @sha3_384 -> :sha3_384
      _ -> "unknown hash method"
    end
  end

end
