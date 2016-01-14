defmodule SecureHeaders.PublicKeyPinsTest do
  use ExUnit.Case, async: true
  alias SecureHeaders.PublicKeyPins  

  #
  # test valid configuration
  #  
  test "should allow string value of public key pins config" do
    assert {:ok, _} = PublicKeyPins.validate([config: [http_public_key_pins: 
    "pin-sha256='b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c'; pin-sha256='73a2c64f9545172c1195efb6616ca5f7afd1df6f245407cafb90de3998a1c97f'; max-age=631138519"]])
  end
  
  test "should allow optional includeSubdomains" do
    assert {:ok, _} = PublicKeyPins.validate([config: [http_public_key_pins: 
    "pin-sha256='b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c'; pin-sha256='73a2c64f9545172c1195efb6616ca5f7afd1df6f245407cafb90de3998a1c97f'; max-age=631138519; includeSubdomains"]])
  end
  
  test "should allow optional report-uri" do
    assert {:ok, _} = PublicKeyPins.validate([config: [http_public_key_pins: 
    "pin-sha256='b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c'; pin-sha256='73a2c64f9545172c1195efb6616ca5f7afd1df6f245407cafb90de3998a1c97f'; max-age=631138519; includeSubdomains; report-uri=https://example.com/"]])
  end

  test "should allow no spaces in config" do
    assert {:ok, _} = PublicKeyPins.validate([config: [http_public_key_pins: 
    "pin-sha256='b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c';pin-sha256='73a2c64f9545172c1195efb6616ca5f7afd1df6f245407cafb90de3998a1c97f';max-age=631138519;includeSubdomains;report-uri=https://example.com/"]])
  end
  
  test "should validate if no pkp config provided" do
    assert {:ok, _} = PublicKeyPins.validate([config: [strict_transport_security: [max_age: "631138519"]]])
  end
  
  #
  # test invalid config with option [warn_only: true] (validate fails with {:error, msg})
  #
  test "validation fails if two fingerprints are not provided (warn_only: true)" do
    assert {:error, "Invalid configuration for public-key-pins"} = 
           PublicKeyPins.validate([warn_only: true, config: [http_public_key_pins: "pin-sha256='b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c'; max-age=631138519"]])
  end
  
  test "validation fails if max-age is not provided (warn_only: true)" do 
    assert {:error, "Invalid configuration for public-key-pins"} = 
           PublicKeyPins.validate([warn_only: true, config: [http_public_key_pins: "pin-sha256='b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c'; pin-sha256='73a2c64f9545172c1195efb6616ca5f7afd1df6f245407cafb90de3998a1c97f'"]])
  end
  
  test "validation fails if invalid config key (warn_only: true)" do
    assert {:error, "Invalid configuration for public-key-pins"} = 
           PublicKeyPins.validate([warn_only: true, config: [http_public_key_pins: "INVALID_PIN-SHA512='b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c'; pin-sha256='73a2c64f9545172c1195efb6616ca5f7afd1df6f245407cafb90de3998a1c97f'; max-age=631138519; includeSubdomains; report-uri=https://example.com/"]])
  end
end
