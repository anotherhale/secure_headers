defmodule SecureHeaders.Mixfile do
  use Mix.Project

  def project do
    [app: :secure_headers,
     version: "1.0.0",
     elixir: "~> 1.5",
     build_embedded: prod?(),
     start_permanent: prod?(),
     deps: deps()]
  end

  defp prod?, do: Mix.env == :prod

  def application do
    [extra_applications: [:logger]]
  end

  defp deps do
    [
     {:pipe, github: "batate/elixir-pipes"},
     {:plug, ">= 1.0.2"}]
  end
end
