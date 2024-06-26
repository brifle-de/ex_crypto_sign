defmodule ExCryptoSign.MixProject do
  use Mix.Project

  def project do
    [
      app: :ex_crypto_sign,
      version: "0.2.1",
      elixir: "~> 1.13",
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      deps: deps(),

      # Docs
      name: "ExCryptoSign",
      source_url: "https://github.com/brifle-de/backend",
      docs: [
        main: "ExCryptoSign", # The main page in the docs
      #  logo: "path/to/logo.png",
        extras: ["README.md"]
      ]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :crypto, :xmerl]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:xml_builder, "~> 2.2"},
      {:xmerl_c14n, "~> 0.2.0"},
      {:x509, "~> 0.8.8"},
      {:sweet_xml, "~> 0.7.4"},
      {:starkbank_ecdsa, "~> 1.1"},
      # {:dep_from_hexpm, "~> 0.3.0"},
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"}
      # for documentation
      {:ex_doc, "~> 0.31", only: :dev, runtime: false},
    ]
  end
end
