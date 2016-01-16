defmodule SecureHeaders.XContentTypeOptionsTest do
  use ExUnit.Case, async: true
  alias SecureHeaders.XContentTypeOptions
  
  #
  # test valid configuration
  #  
  test "should allow string value 'nosniff'" do
    assert {:ok, _} = XContentTypeOptions.validate([config: [x_content_type_options: "nosniff"]])
  end
  
  test "should allow x_download_option: false" do
    assert {:ok, _} = XContentTypeOptions.validate([config: [x_content_type_options: false]])
  end
  
  test "should allow x_download_option: nil" do
    assert {:ok, _} = XContentTypeOptions.validate([config: [x_content_type_options: nil]])
  end
    
  test "should validate if no x-content-type config is provided" do
    assert {:ok, [config: [x_xss_protection: "0"]]} = XContentTypeOptions.validate([config: [x_xss_protection: "0"]])
  end
 
  #
  # test invalid config with option [warn_only: true] (validate fails with {:error, msg})
  #
  test "validation fails if value is invalid  (warn_only: true)" do
     assert {:error, "Invalid configuration for x-content-type-options. Valid values are 'nosniff', nil, or false"} = 
            XContentTypeOptions.validate([warn_only: true, config: [x_content_type_options: "INVALID_CONFIG"]])
  end
   
  test "validation fails if value is true (warn_only: true)" do
     assert {:error, "Invalid configuration for x-content-type-options. Valid values are 'nosniff', nil, or false"} = 
            XContentTypeOptions.validate([warn_only: true, config: [x_content_type_options: true]])
  end
end
