defmodule ExCryptoSign.Constants.NamedCurves do

  def secp256r1 do
    "urn:oid:1.2.840.10045.3.1.7"
  end

  def get_w3_url(atom) do
    case atom do
      :secp256r1 -> secp256r1()
      _ -> "unknown curve"
    end
  end

end
