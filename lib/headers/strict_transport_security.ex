defmodule SecureHeaders.StrictTrasportSecurity do

  @valid_header  ~r/\Amax-age=\d+(; includeSubdomains)?(; preload)?\z/i
  @error_msg "Invalid configuration for strict-transport-security"
  @secure_config [
    max_age: 631138519,
    includesubdomains: false,
    preload: false
  ]

  def validate(options) when options |> is_list do
    case Keyword.has_key?(options, :config) do 
      false -> {:ok, options}
      true  -> 
      case Keyword.has_key?(options[:config], :strict_transport_security) do
        # No strict-transport-security configuration found - return config
        false -> {:ok, options}
        true  ->
        case validate_config(options[:config][:strict_transport_security]) do
          false -> {:error, @error_msg}
          true  ->
              IO.puts "validate_config: "
             IO.inspect  options
            {:ok, config_to_string(options, options[:config][:strict_transport_security])}
        end
      end 
    end
  end  

  def validate(_),  do: {:error, @error_msg}

  defp config_to_string(options, sts_config) when sts_config |> is_list do
    config = Keyword.drop(options[:config], [:strict_transport_security]) 
    IO.inspect config
    config = config ++ [strict_transport_security: make_string(sts_config)]
    IO.inspect config
    Keyword.drop(options, [:config]) ++ [config: config]
  end

  defp config_to_string(options, sts_config) when sts_config |> is_bitstring do
    options
  end

  defp validate_config(sts_config) when sts_config |> is_list do
    case validate_keys(sts_config) do
      false -> false
      true  -> validate_config(make_string(sts_config))
    end  
  end

  defp validate_config(sts_config) when sts_config |> is_bitstring do
    Regex.match?( @valid_header, sts_config) 
  end

  defp validate_config(sts_config) when sts_config |> is_number do
    Regex.match?( @valid_header, Integer.to_string(sts_config)) 
  end

  defp validate_config(_), do: {:error, @error_msg}

  defp validate_keys(sts_config) when sts_config |> is_list do
    List.foldl( Keyword.keys(sts_config), true, fn (key,acc) -> List.keymember?(@secure_config,key,0) && acc end)
  end

  defp make_string(sts_config) do
    max_age = append_max_age(sts_config[:max_age])
    if max_age && Regex.match?(~r/^max-age=\d+$/,max_age) do 
      result = append_max_age(max_age)
    end
    if Keyword.get(sts_config, :includesubdomains), do: result = result <> "; includeSubdomains"
    if Keyword.get(sts_config, :preload), do: result = result <> "; preload"
    result
  end

  defp append_max_age(ma) when ma |> is_bitstring, do: "max-age="<>ma
  defp append_max_age(ma) when ma |> is_number, do: "max-age"<>Integer.to_string(ma)
  defp append_max_age(_), do: "" 
end
