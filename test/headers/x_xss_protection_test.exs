defmodule SecureHeaders.XXssProtectionTest do
  use ExUnit.Case, async: true
  alias SecureHeaders.XXssProtection

  #
  # test valid configuration
  #
  test "should allow value=0" do
    assert {:ok, _} = XXssProtection.validate([config: [x_xss_protection: [value: 0]]])
  end
  
  test "should allow value=1" do
    assert {:ok, _} = XXssProtection.validate([config: [x_xss_protection: [value: 1]]])
  end
  
  test "should allow value=1 with mode" do  
    assert {:ok, _} = XXssProtection.validate([config: [x_xss_protection: [value: 1, mode: "block"]]])
  end
  
  test "should allow value=1 with report" do  
    assert {:ok, _} = XXssProtection.validate([config: [x_xss_protection: [value: 1, report: "https://example.com/"]]])
  end

  test "should allow value=1 with mode and report" do    
    assert {:ok, _} = XXssProtection.validate([config: [x_xss_protection: [value: 1, mode: "block", report: "https://example.com/report"]]])
  end
  
  test "should allow value=1 with mode and report relative URL" do    
    assert {:ok, _} = XXssProtection.validate([config: [x_xss_protection: [value: 1, mode: "block", report: "/report/"]]])
  end
  
  test "should allow value=0 as string" do    
    assert {:ok, _} = XXssProtection.validate([config: [x_xss_protection: "0"]])
  end  

  test "should allow value=0 as string and semicolon" do        
    assert {:ok, _} = XXssProtection.validate([config: [x_xss_protection: "0;"]])
  end  
 
  test "should allow value=1 as string" do     
    assert {:ok, _} = XXssProtection.validate([config: [x_xss_protection: "1"]])
  end    
    
  test "should allow value=1; as string" do     
    assert {:ok, _} = XXssProtection.validate([config: [x_xss_protection: "1;"]])
  end    
    
  test "should allow value=1 and mode with no space as string" do     
    assert {:ok, _} = XXssProtection.validate([config: [x_xss_protection: "1;mode=block"]])
  end    

  test "should allow value=1 and mode as string" do      
    assert {:ok, _} = XXssProtection.validate([config: [x_xss_protection: "1; mode=block"]])
  end    

  test "should allow value=1 and report as string" do      
    assert {:ok, _} = XXssProtection.validate([config: [x_xss_protection: "1; report=https://example.com/"]])
  end    
    
  test "should allow value=1 and report relative URL as string" do          
    assert {:ok, _} = XXssProtection.validate([config: [x_xss_protection: "1; report=/google.com/"]])
  end    
    
  test "should allow value=1, mode, and report with relative URL as string" do          
    assert {:ok, _} = XXssProtection.validate([config: [x_xss_protection: "1; mode=block; report=/google.com/"]])
  end    
  
  test "should allow value=1, mode, and report as string" do              
    assert {:ok, _} = XXssProtection.validate([config: [x_xss_protection: "1; mode=block; report=https://example.com/"]])
  end    
  
  test "should validate if no x-xss-protection config is provided" do
    assert {:ok, [config: [x_content_type_options: "nosniff"]]} = XXssProtection.validate([config: [x_content_type_options: "nosniff"]])
  end
  
  #
  # Invalid config test - option [warn_only: true] (validate fails with {:error, msg})
  #
  test "invalid configuration (warn_only: true)" do
    assert {:error, "Invalid configuration for x-xss-protection"} =  
           XXssProtection.validate([warn_only: true, config: [x_xss_protection: [value: 0, mode: "block"]]])
    assert {:error, "Invalid configuration for x-xss-protection"} = 
           XXssProtection.validate([warn_only: true, config: [x_xss_protection: [value: 0, report: "https://example.com/"]]])
    assert {:error, "Invalid configuration for x-xss-protection"}  = 
           XXssProtection.validate([warn_only: true, config: [x_xss_protection: [value: 0, mode: "block", report: "https://example.com/"]]])
    assert {:error, "Invalid configuration for x-xss-protection"}  = 
           XXssProtection.validate([warn_only: true, config: [x_xss_protection: [value: 0, mode: "block", report: "/report/"]]])
    assert {:error, "Invalid configuration for x-xss-protection"}  = 
           XXssProtection.validate([warn_only: true, config: [x_xss_protection: [value: 1, mode: "INVALID_CONFIG"]]])
    assert {:error, "Invalid configuration for x-xss-protection"}  = 
           XXssProtection.validate([warn_only: true, config: [x_xss_protection: [value: 1, mode: "INVALID_CONFIG", report: "https://example.com/"]]])
    assert {:error, "Invalid configuration for x-xss-protection"}  = 
           XXssProtection.validate([warn_only: true, config: [x_xss_protection: [value: 2, mode: "block"]]])
    assert {:error, "Invalid configuration for x-xss-protection"}  = 
           XXssProtection.validate([warn_only: true, config: [x_xss_protection: [value: 2, modes: "block"]]])
    assert {:error, "Invalid configuration for x-xss-protection"}  = 
           XXssProtection.validate([warn_only: true, config: [x_xss_protection: [value: 2, mode: "INVALID_CONFIG"]]])
    assert {:error, "Invalid configuration for x-xss-protection"}  = 
           XXssProtection.validate([warn_only: true, config: [x_xss_protection: [value: 2, report: "google.com"]]])
    assert {:error, "Invalid configuration for x-xss-protection"}  = 
           XXssProtection.validate([warn_only: true, config: [x_xss_protection: [value: 2, mode: "INVALID_CONFIG", report: "https://example.com/"]]])
    assert {:error, "Invalid configuration for x-xss-protection"}  = 
           XXssProtection.validate([warn_only: true, config: [x_xss_protection: [value: 2, mode: "block", report: "google.com"]]])
    assert {:error, "Invalid configuration for x-xss-protection"}  = 
           XXssProtection.validate([warn_only: true, config: [x_xss_protection: [values: 2]]])
    assert {:error, "Invalid configuration for x-xss-protection"}  = 
           XXssProtection.validate([warn_only: true, config: [x_xss_protection: [value: 2, modez: "block", report: "google.com"]]])        
    assert {:error, "Invalid configuration for x-xss-protection"}  = 
           XXssProtection.validate([warn_only: true, config: [x_xss_protection: [value: 2, reportz: "google.com"]]])
  end
end
