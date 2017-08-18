defmodule SecureHeaders.ClearSiteData do
  
  # https://w3c.github.io/webappsec-clear-site-data/

  @error_msg "Invalid configuration for clear-site-data"  
  @valid_header ~r/\A(cache\z|cookies\z|storage\z|executioncontexts)/i

  def validate(options) when is_list(options) do
    case Keyword.has_key?(options, :config) do 
      false -> {:ok, options}
      true  -> 
      case Keyword.has_key?(options[:config], :clear_site_data) do
        # No clear_site_data configuration found - return config
        false -> {:ok, options}
        true  -> 
          case validate_config(options[:config]) do
            false -> {:error, @error_msg}
            true  -> {:ok, options}
          end
      end
    end
  end  
  
  def validate(_),  do: {:error, @error_msg}

  defp validate_config(config) when config |> is_list do
    validate_value(config[:clear_site_data])
  end

  defp validate_config(config) when config |> is_boolean do
    validate_value(config[:clear_site_data])
  end

  defp validate_value(config) when config |> is_bitstring do
    Regex.match?( @valid_header, config)
  end
  
  defp validate_value(config) do
    !config
  end

end
