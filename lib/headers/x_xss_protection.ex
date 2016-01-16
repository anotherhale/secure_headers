defmodule SecureHeaders.XXssProtection do

  @moduledoc '''
 IO.inspect( SecureHeaders.XXssProtection.validate [x_xss_protection: [value: 0]])
 IO.inspect( SecureHeaders.XXssProtection.validate [x_xss_protection: [value: 1]])
 IO.inspect( SecureHeaders.XXssProtection.validate [x_xss_protection: [value: 1, mode: "block"]])
 IO.inspect( SecureHeaders.XXssProtection.validate [x_xss_protection: [value: 1, report: "http://google.com/"]])
 IO.inspect( SecureHeaders.XXssProtection.validate [x_xss_protection: [value: 1, mode: "block", report: "http://google.com/report"]])
 IO.inspect( SecureHeaders.XXssProtection.validate [x_xss_protection: [value: 1, mode: "block", report: "/report/"]])
 IO.inspect( SecureHeaders.XXssProtection.validate [x_xss_protection: "0"])
 IO.inspect( SecureHeaders.XXssProtection.validate [x_xss_protection: "0;"])
 IO.inspect( SecureHeaders.XXssProtection.validate [x_xss_protection: "1"])
 IO.inspect( SecureHeaders.XXssProtection.validate [x_xss_protection: "1;"])
 IO.inspect( SecureHeaders.XXssProtection.validate [x_xss_protection: "1;mode=block"])
 IO.inspect( SecureHeaders.XXssProtection.validate [x_xss_protection: "1; mode=block"])
 IO.inspect( SecureHeaders.XXssProtection.validate [x_xss_protection: "1; report=http://google.com/"])
 IO.inspect( SecureHeaders.XXssProtection.validate [x_xss_protection: "1; report=/google.com/"])
 IO.inspect( SecureHeaders.XXssProtection.validate [x_xss_protection: "1; mode=block; report=/google.com/"])
 IO.inspect( SecureHeaders.XXssProtection.validate [x_xss_protection: "1; mode=block; report=http://google.com/"])
 
 
 IO.inspect( SecureHeaders.XXssProtection.validate [x_xss_protection: [value: 0, mode: "block"]])
 IO.inspect( SecureHeaders.XXssProtection.validate [x_xss_protection: [value: 0, report: "http://google.com/"]])
 IO.inspect( SecureHeaders.XXssProtection.validate [x_xss_protection: [value: 0, mode: "block", report: "http://google.com/"]])
 IO.inspect( SecureHeaders.XXssProtection.validate [x_xss_protection: [value: 0, mode: "block", report: "/report/"]])
 IO.inspect( SecureHeaders.XXssProtection.validate [x_xss_protection: [value: 1, mode: "allow"]])
 IO.inspect( SecureHeaders.XXssProtection.validate [x_xss_protection: [value: 1, mode: "allow", report: "http://google.com/"]])
 IO.inspect( SecureHeaders.XXssProtection.validate [x_xss_protection: [value: 2, mode: "block"]])
 IO.inspect( SecureHeaders.XXssProtection.validate [x_xss_protection: [value: 2, modes: "block"]])
 IO.inspect( SecureHeaders.XXssProtection.validate [x_xss_protection: [value: 2, mode: "allow"]])
 IO.inspect( SecureHeaders.XXssProtection.validate [x_xss_protection: [value: 2, report: "google.com"]])
 IO.inspect( SecureHeaders.XXssProtection.validate [x_xss_protection: [value: 2, mode: "allow", report: "http://google.com/"]])
 IO.inspect( SecureHeaders.XXssProtection.validate [x_xss_protection: [value: 2, mode: "block", report: "google.com"]])
 IO.inspect( SecureHeaders.XXssProtection.validate [x_xss_protection: [values: 2]])
 IO.inspect( SecureHeaders.XXssProtection.validate [x_xss_protection: [value: 2, reportz: "google.com"]])
 IO.inspect( SecureHeaders.XXssProtection.validate [x_xss_protection: [valuez: 2, mode: "block", reportz: "google.com"]])
  '''
  @error_msg "Invalid configuration for x-xss-protection"
  @secure_config [
    value: 0,
    mode: "block",
    report: ""
  ]    

  def validate(options) when is_list(options) do
    case Keyword.has_key?(options, :config) do 
      false -> {:ok, options}
      true  -> 
      case Keyword.has_key?(options[:config], :x_xss_protection) do
        # No x-xss-protection configuration found - return config
        false -> {:ok, options}
        true  ->
        case validate_config(options[:config][:x_xss_protection]) do
          false -> {:error, @error_msg}
          true  -> {:ok, config_to_string(options, options[:config][:x_xss_protection])}
        end
      end 
    end
  end  
  
  def validate(_),  do: {:error, @error_msg}

  defp config_to_string(options, xss_config) when xss_config |> is_list do
    config = Keyword.drop(options[:config], [:x_xss_protection]) 
    config = config ++ [x_xss_protection: make_string(xss_config)]
    Keyword.drop(options, [:config]) ++ [config: config]
  end

  defp config_to_string(options, xss_config) when xss_config |> is_bitstring do
    options
  end

  defp validate_config(xss_config) when is_list(xss_config) do
    case validate_keys(xss_config) do
      false -> false
      true  -> validate_config(make_string(xss_config))
    end  
  end

  defp validate_config(xss_config) when xss_config |> is_bitstring do
    v = ~r/^[01](;)?\z/i
    vm  = ~r/^[1](;|; ){1,1}mode=block\z/i
    vr= ~r/^[1](;|; ){1,1}report=.+\z/i
    vmr = ~r/^[1](;|; ){1,1}mode=block(;|; ){1,1}report=.+\z/i
    Regex.match?(v, xss_config) || Regex.match?(vm, xss_config)|| Regex.match?(vr, xss_config) || Regex.match?(vmr, xss_config)  
  end

  defp validate_config(_), do: {:error, @error_msg}

  defp validate_keys(xss_config) when xss_config |> is_list do
    List.foldl( Keyword.keys(xss_config), true, fn (key,acc) -> List.keymember?(@secure_config,key,0) && acc end)
  end
  
  defp make_string(xss_config) do
    result = ""
    if Keyword.get(xss_config, :value), do: result = result <> Integer.to_string(xss_config[:value])
    if Keyword.get(xss_config, :mode), do: result = result <> "; mode=" <> xss_config[:mode]
    if Keyword.get(xss_config, :report), do: result =  result <> "; report=" <> xss_config[:report]
    result
  end
end
