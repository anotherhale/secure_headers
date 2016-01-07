defmodule PlugSecureHeaders.PlugSecureHeadersTest do

  use ExUnit.Case, async: true
  use Plug.Test
  alias Plug.Conn.Status
  @opts AppRouter.init([])
  
  test "request with default secure headers" do
    connection = conn(:get, "/")
    response = TestApp.call(connection, [])

    assert conn.state == :sent
    assert conn.status == 200  
    assert response.status == Status.code(:ok)
    assert response.resp_headers == [
      {"cache-control", "max-age=0, private, must-revalidate"},
      {"content-security-policy", "default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self';"},
      {"http-public-key-pins", ""},
      {"strict-transport-security", "max-age=631138519"},
      {"x-content-type-options", "nosniff"},
      {"x-download-options", "noopen"},
      {"x-frame-options", "sameorigin"},
      {"x-permitted-cross-domain-policies", "none"},
      {"x-xss-protection", "1; mode=block"}
    ]
  end

  test "request with default custom secure headers" do
    connection = conn(:get, "/")
    response = CustomTestApp.call(connection, [])
  
    assert conn.state == :sent
    assert conn.status == 200  
    assert response.status == Status.code(:ok)
    assert response.resp_headers == [
      {"cache-control", "max-age=0, private, must-revalidate"},
      {"content-security-policy", "default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self';"}
    ]
  end

  test "request with default custom secure headers merge_configs=false" do
    connection = conn(:get, "/")
    response = CustomTestAppMergeConfigFalse.call(connection, [])
  
    assert conn.state == :sent
    assert conn.status == 200  
    assert response.status == Status.code(:ok)
    assert response.resp_headers == [
      {"cache-control", "max-age=0, private, must-revalidate"}, 
      {"content-security-policy", "default-src 'none';"}
    ]
  end

  test "default request with options merge_configs=true" do
    connection = conn(:get, "/")
    response = CustomTestAppMergeConfigTrue.call(connection, [])
  
    assert conn.state == :sent
    assert conn.status == 200  
    assert response.status == Status.code(:ok)
    assert response.resp_headers ==  [
      {"cache-control", "max-age=0, private, must-revalidate"}, 
      {"content-security-policy", "default-src 'none';"}, 
      {"http-public-key-pins", ""}, 
      {"strict-transport-security", "max-age=631138519"}, 
      {"x-content-type-options", "nosniff"}, 
      {"x-download-options", "noopen"}, 
      {"x-frame-options", "sameorigin"}, 
      {"x-permitted-cross-domain-policies", "none"}, 
      {"x-xss-protection", "1; mode=block"}
    ]
  end


  test "secureAppRouter returns default config" do
    # Create a test connection
    conn = conn(:get, "/")

    # Invoke the plug
    conn = SecureAppRouter.call(conn, SecureAppRouter.init())

    # Assert the response and status
    assert conn.state == :sent
    assert conn.status == 200
    assert conn.resp_body == "default config"
    assert response.resp_headers == [
      {"cache-control", "max-age=0, private, must-revalidate"},
      {"content-security-policy", "default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self';"},
      {"http-public-key-pins", ""},
      {"strict-transport-security", "max-age=631138519"},
      {"x-content-type-options", "nosniff"},
      {"x-download-options", "noopen"},
      {"x-frame-options", "sameorigin"},
      {"x-permitted-cross-domain-policies", "none"},
      {"x-xss-protection", "1; mode=block"}
    ]
  end

  test "customAppRouter returns custom config" do
    # Create a test connection
    conn = conn(:get, "/custom")

    # Invoke the plug
    conn = CustomAppRouter.call(conn, CustomAppRouter.init())

    # Assert the response and status
    assert conn.state == :sent
    assert conn.status == 200
    assert conn.resp_body == "custom config"
    assert response.resp_headers == [
      {"cache-control", "max-age=0, private, must-revalidate"},
      {"content-security-policy", "default-src 'none';"},
      {"strict-transport-security", "max-age=631138519"},
      {"x-permitted-cross-domain-policies", "none"},
      {"x-xss-protection", "1; mode=block"}
    ]
  end


  test "should allow empty config" do 
    assert {:ok, _} = PlugSecureHeaders.PlugSecureHeaders.validate([])
  end

  test "should allow empty config with options" do 
    assert {:ok, _} = PlugSecureHeaders.PlugSecureHeaders.validate([warn_only: true])
   end

  test "should allow config with no options" do
    assert {:ok, _} = PlugSecureHeaders.PlugSecureHeaders.validate([config: [x_content_type_options: "nosniff"]])
  end
    
  test "should allow config with options" do 
    assert {:ok, _} = PlugSecureHeaders.PlugSecureHeaders.validate([warn_only: true, config: [x_content_type_options: "nosniff"]])
  end

  test "should allow use_secure_config: false to return options with no config" do
    assert {:ok, [use_secure_config: false]} = PlugSecureHeaders.PlugSecureHeaders.validate([use_secure_config: false])
  end
  
  test "raises an exception if invalid option" do
     assert_raise ArgumentError, "Invalid configuration for PlugSecureHeaders", fn -> PlugSecureHeaders.PlugSecureHeaders.validate([INVALID_OPTION: false]) end
  end

  test "raises an exception if warn_only: is not a boolean" do 
     assert_raise ArgumentError, "Invalid configuration for PlugSecureHeaders", fn -> PlugSecureHeaders.PlugSecureHeaders.validate([warn_only: "INVALID_CONFIG"]) end
  end

  test "raises an exception if use_secure_config: is not a boolean" do
     assert_raise ArgumentError, "Invalid configuration for PlugSecureHeaders", fn -> PlugSecureHeaders.PlugSecureHeaders.validate([use_secure_config: "INVALID_CONFIG"]) end
  end

  test "raises an exception if merge_config: is not a boolean" do
     assert_raise ArgumentError, "Invalid configuration for PlugSecureHeaders", fn -> PlugSecureHeaders.PlugSecureHeaders.validate([merge_config: "INVALID_CONFIG"]) end
  end

  test "validation fails if invalid option" do
     assert {:error, "Invalid configuration for PlugSecureHeaders"} = PlugSecureHeaders.PlugSecureHeaders.validate([warn_only: true, INVALID_OPTION: false])
  end
     
  test "validation fails if use_secure_config: is not a boolean" do
     assert {:error, "Invalid configuration for PlugSecureHeaders"} = PlugSecureHeaders.PlugSecureHeaders.validate([warn_only: true, use_secure_config: "INVALID_CONFIG"])
  end

  test "validation fails if merge_config: is not a boolean" do
     assert {:error, "Invalid configuration for PlugSecureHeaders"} = PlugSecureHeaders.PlugSecureHeaders.validate([warn_only: true, merge_config: "INVALID_CONFIG"])
  end
end
