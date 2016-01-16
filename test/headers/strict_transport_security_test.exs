defmodule SecureHeaders.StrictTrasportSecurityTest do
  use ExUnit.Case, async: true
    
    """
  #
  # test valid config
  #
  test "should allow string values for max-age" do
    assert {:ok, _} = StrictTrasportSecurity.validate([config: [strict_transport_security: [max_age: "631138519"]]])    
  end
    
  test "should allow integer values for max-age" do
    assert {:ok, _} = StrictTrasportSecurity.validate([config: [strict_transport_security: [max_age: 631138519]]])    
  end
    
  test "should allow a string argument" do
    assert {:ok, _} = StrictTrasportSecurity.validate([config: [strict_transport_security: "max-age=631138519"]])    
  end

  test "should allow includeSubdomains: true" do
    assert {:ok, _} = StrictTrasportSecurity.validate([config: [strict_transport_security: [max_age: "631138519", includeSubdomains: true]]])    
  end
    
  test "should allow includeSubdomains: false" do
    assert {:ok, _} = StrictTrasportSecurity.validate([config: [strict_transport_security: [max_age: "631138519", includeSubdomains: false]]])    
  end
   
  test "should allow preload: true" do
    assert {:ok, _} = StrictTrasportSecurity.validate([config: [strict_transport_security: [max_age: "631138519", preload: true]]])    
  end
    
  test "should allow preload: false" do
    assert {:ok, _} = StrictTrasportSecurity.validate([config: [strict_transport_security: [max_age: "631138519", preload: false]]])    
  end
    
  test "should allow preload: and includeSubdomains: " do
    assert {:ok, _} = StrictTrasportSecurity.validate([config: [strict_transport_security: [max_age: "631138519", includeSubdomains: true, preload: true]]])       
  end
    
  test "should validate if no strict-transport-security is configured" do
    assert {:ok, _} = StrictTrasportSecurity.validate([config: [x_download_options: "noopen"]])    
  end
   
  #
  # test invalid config with option [warn_only: true] (validate fails with {:error, msg})
  #
  test "an error is returned if max-age is not a number" do
     assert {:error, "Invalid configuration for strict-transport-security"} = 
            StrictTrasportSecurity.validate([warn_only: true, config: [strict_transport_security: [max_age: "INVALID_CONFIG"]]])
  end
  test "an error is returned if max-age is not supplied" do
     assert {:error, "Invalid configuration for strict-transport-security"} = 
            StrictTrasportSecurity.validate([warn_only: true, config: [strict_transport_security: [includeSubdomains: true]]])
  end
  test "an error is returned if includeSubdomains is not a boolean" do
     assert {:error, "Invalid configuration for strict-transport-security"} = 
            StrictTrasportSecurity.validate([warn_only: true, config: [strict_transport_security: [includeSubdomains: "INVALID_CONFIG"]]])
  end

  test "an error is returned if preload is not a boolean" do
     assert {:error, "Invalid configuration for strict-transport-security"} =
            StrictTrasportSecurity.validate([warn_only: true, config: [strict_transport_security: [preload: "INVALID_CONFIG"]]])
  end

  test "an error is returned with an invalid format" do
     assert {:error, "Invalid configuration for strict-transport-security"} = 
            StrictTrasportSecurity.validate([warn_only: true, config: [strict_transport_security: [max_age: false, includeSubdomains: true]]])
  end
     
  test "an error is returned with an invalid config" do
     assert {:error, "Invalid configuration for strict-transport-security"} = 
            StrictTrasportSecurity.validate([warn_only: true, config: [strict_transport_security: "max-age=631138519;includeSubdomains;INVALID_CONFIG"]])     
  end
  """
end
