defmodule SecureHeaders.XFrameOptionsTest do
  use ExUnit.Case, async: true
  alias SecureHeaders.XFrameOptions
  
  #
  # test valid config 
  #
  test "should allow string value 'deny'" do
    assert {:ok, _} = XFrameOptions.validate([config: [x_frame_options: "deny"]])
  end
  
  test "should allow string value 'sameorigin'" do 
    assert {:ok, _} = XFrameOptions.validate([config: [x_frame_options: "sameorigin"]])
  end
  
  test "should allow x_frame_options: 'allow-from REQ_URL'" do
    assert {:ok, _} = XFrameOptions.validate([config: [x_frame_options: "allow-from https://example.com"]])
  end
  
  #
  # test invalid config with option [warn_only: true] (validate fails with {:error, msg})
  #
  test "validation fails if value is not 'deny', 'sameorigin', or 'allow-from REQ_URL' (warn_only: true)" do
     assert {:error, "Invalid configuration for x-frame-options"} = 
            XFrameOptions.validate([warn_only: true, config: [x_frame_options: "INVALID_CONFIG"]])
  end
  
  test "validation fails if value 'allow-from' does not have REQ_URL (warn_only: true)" do
     assert {:error, "Invalid configuration for x-frame-options"} = 
            XFrameOptions.validate([warn_only: true, config: [x_frame_options: "allow-from"]])  
  end
end
