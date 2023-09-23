defmodule ExCryptoSign.Constants.CanonicalizationMethods do

  @exclusive "http://www.w3.org/2001/10/xml-exc-c14n#"
  @exclusive_with_comments "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
  @inclusive "http://www.w3.org/TR/2000/WD-xml-c14n-20010315"
  @inclusive_with_comments "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"


  def get_exclusive do
    @exclusive
  end

  def get_exclusive_with_comments do
    @exclusive_with_comments
  end

  def get_inclusive do
    @inclusive
  end

  def get_inclusive_with_comments do
    @inclusive_with_comments
  end

  def get_w3_url(atom) do
    case atom do
      :exclusive -> @exclusive
      :exclusive_with_comments -> @exclusive_with_comments
      :inclusive -> @inclusive
      :inclusive_with_comments -> @inclusive_with_comments
      _ -> "unknown canonicalization method"
    end
  end

  def from_w3_url(url) do
    case url do
      @exclusive -> :exclusive
      @exclusive_with_comments -> :exclusive_with_comments
      @inclusive -> :inclusive
      @inclusive_with_comments -> :inclusive_with_comments
      _ -> "unknown canonicalization method"
    end
  end

end
