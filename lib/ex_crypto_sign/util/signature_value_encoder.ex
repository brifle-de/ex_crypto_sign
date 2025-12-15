defmodule ExCryptoSign.Util.SignatureValueEncoder do


  defstruct [
    type: :ecdsa,
    ecdsa: %{
      r: nil,
      s: nil
    },
    rsa: %{
      value: nil
    }
  ]

   @doc """
  computes the length of the key in bytes
  """
  defp compute_ecc_key_length(private_key) do
    :public_key.pem_decode(private_key)
    |> hd()
    |> :public_key.pem_entry_decode()
    |> then(fn {:ECPrivateKey, 1, key, _, _, _} -> key end)
    |> byte_size()
  end

  def parse_signature_value!(:ecdsa, base64_signature) do
    decoded = Base.decode64!(base64_signature)
    case signature_format_ecdsa(decoded) do
      :der -> parse_der_ecdsa!(base64_signature)
      :raw -> parse_raw_ecdsa(decoded)
    end
  end


  defp parse_der_ecdsa!(base64_signature) do
     %EllipticCurve.Signature{
      r: r,
      s: s
    }  = EllipticCurve.Signature.fromBase64!(base64_signature)

    %ExCryptoSign.Util.SignatureValueEncoder{
      type: :ecdsa,
      ecdsa: %{
        r: r,
        s: s
      }
    }
  end

  defp signature_format_ecdsa(sig) when is_binary(sig) do
    case sig do
      <<0x30, _rest::binary>> -> :der
      _ -> :raw
    end
  end

  defp parse_raw_ecdsa(value) do
    key_length = byte_size(value) |> div(2)

    <<r::binary-size(key_length), s::binary-size(key_length)>> = value

    r_int = :binary.decode_unsigned(r)
    s_int = :binary.decode_unsigned(s)

    %ExCryptoSign.Util.SignatureValueEncoder{
      type: :ecdsa,
      ecdsa: %{
        r: r_int,
        s: s_int
      }
    }
  end

  @doc """
  parses the signature value from base64 encoded string
  """
  def parse_signature_value!(:rsa, base64_signature) do
    signature = Base.decode64!(base64_signature)

    %ExCryptoSign.Util.SignatureValueEncoder{
      type: :rsa,
      rsa: %{
        value: signature
      }
    }
  end

  @doc """
  converts the signature value to base64 DER format
  """
  def to_base64(%ExCryptoSign.Util.SignatureValueEncoder{type: :rsa, rsa: %{value: value}}) do
    Base.encode64(value)
  end

  @doc """
  converts the signature value to base64 DER format
  """
  def to_base64(%ExCryptoSign.Util.SignatureValueEncoder{type: :ecdsa, ecdsa: %{r: r, s: s}}) do
    %EllipticCurve.Signature{
      r: r,
      s: s
    }
    |> EllipticCurve.Signature.toBase64()
  end


  @doc """
  converts the signature value to raw format
  """
  def to_raw_signature(%ExCryptoSign.Util.SignatureValueEncoder{type: :rsa, rsa: %{value: value}}, _key_length_bytes) do
    Base.encode64(value)
  end

  @doc """
  converts the signature value to raw format
  """
  def to_raw_signature(%ExCryptoSign.Util.SignatureValueEncoder{type: :ecdsa, ecdsa: %{r: r, s: s}}, key_length_bytes) do

    # half key length for r and s and convert to interger
    size = (key_length_bytes / 2 ) |> round()

    r_bytes = integer_to_bytes(r, size)
    s_bytes = integer_to_bytes(s, size)

    signature_bytes = <<r_bytes::binary, s_bytes::binary>>
    Base.encode64(signature_bytes)
  end

  defp integer_to_bytes(integer, byte_length) do
    :binary.encode_unsigned(integer)
    |> pad_left(byte_length)
  end

  defp pad_left(binary, byte_length) do
    padding_length = byte_length - byte_size(binary)
    padding = :binary.copy(<<0>>, padding_length)
    <<padding::binary, binary::binary>>
  end

  @doc """
  converts the signature value to binary DER format
  """
  def to_binary(%ExCryptoSign.Util.SignatureValueEncoder{type: :rsa, rsa: %{value: value}}) do
    value
  end
  def to_binary(%ExCryptoSign.Util.SignatureValueEncoder{type: :ecdsa, ecdsa: %{r: r, s: s}}) do
      %EllipticCurve.Signature{
        r: r,
        s: s
      }
      |> EllipticCurve.Signature.toDer()
  end

end
