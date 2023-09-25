defmodule ExCryptoSign.Util.PemCertificate do
  @spec get_certificate_digest(binary, any) :: binary
  def get_certificate_digest(pem_data, digest_method) do

      X509.Certificate.from_pem!(pem_data)
      |> X509.Certificate.to_der()
      |> then(fn c -> :crypto.hash(digest_method, c) end)
      |> Base.encode64()
    end

  def get_certificate_issuer(pem_data) do


    X509.Certificate.from_pem!(pem_data)
    |> X509.Certificate.issuer("CN")
    |> Enum.at(0)
  end

  def get_certificate_serial(pem_data) do
    X509.Certificate.from_pem!(pem_data)
    |> X509.Certificate.serial()
    |> to_string()
  end



  @spec parse_time_string({:utcTime, binary}) :: non_neg_integer
  def parse_time_string({:utcTime, date_string}) do


    [year, month, day, hour, minute, second | _rest] =
      date_string
      |> to_string()
      |> String.split(~r/\d{2}/,include_captures: true)
      |> Enum.filter(fn n -> n != "" end)

    # get current century
    {{year_4_digit,_,_}, _} = :calendar.now_to_universal_time(:erlang.timestamp())

    # year to interger
    i_year = String.to_integer(year)

    # assume century from current year
    assumed_full_year = year_4_digit
    |> Kernel./(100)
    |> floor
    |> Kernel.*(100)
    |> Kernel.+(i_year)

    # if the age is more than 70 years in the future, we go back one century,
    # because we assume the certificate was issued in the last century

    full_year = if assumed_full_year - year_4_digit > 70 do
      assumed_full_year - 100
    else
      assumed_full_year
    end

    {{full_year, String.to_integer(month), String.to_integer(day)},
     {String.to_integer(hour), String.to_integer(minute), String.to_integer(second)}}
    |> :calendar.datetime_to_gregorian_seconds()
    |> DateTime.from_gregorian_seconds()
    |> DateTime.to_unix(:millisecond)

  end

  @spec is_cert_valid_at?(binary, %{
          :calendar => atom,
          :day => any,
          :hour => any,
          :microsecond => any,
          :minute => any,
          :month => any,
          :second => any,
          :std_offset => integer,
          :utc_offset => integer,
          :year => any,
          optional(any) => any
        }) :: boolean
  def is_cert_valid_at?(pem_data, date_time_obj) do

    date_time_obj_ms = (date_time_obj |> DateTime.to_unix(:millisecond))

    X509.Certificate.from_pem!(pem_data)
    |> X509.Certificate.validity()
    |> then(fn {_, start, end_time} -> {parse_time_string(start), parse_time_string(end_time)}  end)
    |> then(fn {start, end_time} -> start <= date_time_obj_ms && end_time >= date_time_obj_ms end)

  end


  def get_public_key(pem) do
    X509.Certificate.from_pem!(pem)
    |> X509.Certificate.public_key()


  end

end
