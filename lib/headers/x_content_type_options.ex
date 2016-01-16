defmodule SecureHeaders.XContentTypeOptions do
  @error_msg "Invalid configuration for x-content-type-options. Valid values are 'nosniff', nil, or false"  
  @valid_header ~r/\Anosniff\z/i

  def validate(options) when is_list(options) do
    case Keyword.has_key?(options, :config) do 
      false -> {:ok, options}
      true  -> 
      case Keyword.has_key?(options[:config], :x_content_type_options) do
        # No x_content_type_options configuration found - return configuration  
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

  defp validate_config(config) do
    validate_value(config[:x_content_type_options])
  end

  defp validate_value(config) when config |> is_bitstring do
    Regex.match?( @valid_header, config)
  end
  
  defp validate_value(config) do
    # unless config[:x_content_type_options]  value is nil or false
    !config
  end
end
