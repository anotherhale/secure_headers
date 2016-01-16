defmodule SecureHeaders.XDownloadOptions do

  @error_msg "Invalid configuration for x-download-options"  
  @valid_header ~r/\Anoopen\z/i

  def validate(options) when is_list(options) do
    case Keyword.has_key?(options, :config) do 
      false -> {:ok, options}
      true  -> 
      case Keyword.has_key?(options[:config], :x_download_options) do
        # No x_download_options configuration found - return config
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
    validate_value(config[:x_download_options])
  end

  defp validate_config(config) when config |> is_boolean do
    validate_value(config[:x_download_options])
  end

  defp validate_value(config) when config |> is_bitstring do
    Regex.match?( @valid_header, config)
  end
  
  defp validate_value(config) do
    !config
  end

end
