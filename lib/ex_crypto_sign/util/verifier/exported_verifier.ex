defmodule ExCryptoSign.Util.Verifier.ExportedVerifier do
alias ExCryptoSign.XmlDocument

  def verify_exported_signature(xml_string) do
    xml_document = XmlDocument.parse_document(xml_string)


    signed_info = xml_document.signed_info
    documents = xml_document.embedded_documents

    ExCryptoSign.Util.Verifier.verifies_document(xml_string, documents)
  end

end
