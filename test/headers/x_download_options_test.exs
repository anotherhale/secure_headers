defmodule SecureHeaders.XDownloadOptionsTest do
  use ExUnit.Case, async: true
  alias SecureHeaders.XDownloadOptions
  
    
  #
  # test valid config
  #
  test "should allow string value 'noopen'" do
    assert {:ok, _} = XDownloadOptions.validate([config: [x_download_options: "noopen"]])
  end
  
  test "should allow x_download_option: false" do
    assert {:ok, _} = XDownloadOptions.validate([config: [x_download_options: false]])
  end
  
  test "should allow x_download_option: nil" do
    assert {:ok, _} = XDownloadOptions.validate([config: [x_download_options: nil]])
  end
  
  #
  # test invalid config with option [warn_only: true] (validate fails with {:error, msg})
  #
  test "validation fails if value is invalid as list (not 'noopen', nil, or false)" do
     assert {:error, "Invalid configuration for x-download-options"} = 
            XDownloadOptions.validate([warn_only: true, config: [x_download_options: "INVALID_CONFIG"]])
  end
  
  test "validation fails if value is true as list (not 'noopen', nil, or false)" do
     assert {:error, "Invalid configuration for x-download-options"} =
            XDownloadOptions.validate([warn_only: true, config: [x_download_options: true]])
  end
end
