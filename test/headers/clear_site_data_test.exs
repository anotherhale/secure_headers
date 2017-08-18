defmodule SecureHeaders.ClearSiteDataTest do
  use ExUnit.Case, async: true
  alias SecureHeaders.ClearSiteData
  
    
  #
  # test valid config
  #
  test "should allow string value 'cache'" do
    assert {:ok, _} = ClearSiteData.validate([config: [clear_site_data: "cache"]])
  end
  
  test "should allow string value 'cookies'" do
    assert {:ok, _} = ClearSiteData.validate([config: [clear_site_data: "cookies"]])
  end

  test "should allow string value 'storage'" do
    assert {:ok, _} = ClearSiteData.validate([config: [clear_site_data: "storage"]])
  end

  test "should allow string value 'executioncontexts'" do
    assert {:ok, _} = ClearSiteData.validate([config: [clear_site_data: "executioncontexts"]])
  end

  test "should allow clear_site_data: false" do
    assert {:ok, _} = ClearSiteData.validate([config: [clear_site_data: false]])
  end
  
  test "should allow clear_site_data: nil" do
    assert {:ok, _} = ClearSiteData.validate([config: [clear_site_data: nil]])
  end
  
  #
  # test invalid config with option [warn_only: true] (validate fails with {:error, msg})
  #
  test "validation fails if value is invalid as list (not 'noopen', nil, or false)" do
     assert {:error, "Invalid configuration for clear-site-data"} = 
            ClearSiteData.validate([warn_only: true, config: [clear_site_data: "INVALID_CONFIG"]])
  end
  
  test "validation fails if value is true as list (not 'noopen', nil, or false)" do
     assert {:error, "Invalid configuration for clear-site-data"} =
            ClearSiteData.validate([warn_only: true, config: [clear_site_data: true]])
  end
end
