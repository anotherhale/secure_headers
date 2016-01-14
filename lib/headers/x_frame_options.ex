defmodule SecureHeaders.XFrameOptions do 

  @valid_header ~r/\A(sameorigin\z|deny\z|allow-from[:\s])/i

  @error_msg "Invalid configuration for x-frame-options"

  def validate(options) when is_list(options) do
    case Keyword.has_key?(options, :config) do 
      false -> {:ok, options}
      true  -> 
      case Keyword.has_key?(options[:config], :x_frame_options) do
        # No http-public-key-pins configuration found - return options
        false -> {:ok, options}
        true  ->
        case validate_config(options[:config][:x_frame_options]) do
          false -> {:error, @error_msg}
          true  -> {:ok, options}
        end
      end 
    end
  end  
  
  def validate(_),  do: {:error, @error_msg}
  
  defp validate_config(x_frame_options) when x_frame_options |> is_bitstring do
    Regex.match?( @valid_header, x_frame_options)
  end

  defp validate_config(x_frame_options) do
    # unless config[:x_frame_options] value is nil or false
    !x_frame_options
  end
end
