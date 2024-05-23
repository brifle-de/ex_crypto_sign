defmodule ExCryptoSign.Constants.TransformMethods do
  @c14n "http://www.w3.org/2001/10/xml-exc-c14n#"
  @xpath "http://www.w3.org/TR/1999/REC-xpath-19991116"

  def get_c14n do
    @c14n
  end

  def get_xpath do
    @xpath
  end

  def get_w3_url(atom) do
    case atom do
      :c14n -> @c14n
      :xpath -> @xpath
      _ -> "unknown transform method"
    end
  end

  def from_w3_url(url) do
    case url do
      @c14n -> :c14n
      @xpath -> :xpath
      _ -> "unknown transform method"
    end
  end

end
