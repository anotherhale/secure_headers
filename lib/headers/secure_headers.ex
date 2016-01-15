defmodule SecureHeaders.SecureHeaders do
  
  
  @error_msg "Invalid configuration for SecureHeaders"
  @secure_config [
    warn_only: false,
    merge: false,
    report_only: false,
    use_secure_config: true,
    config: [
      content_security_policy: "default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self';", 
      http_public_key_pins: "", 
      strict_transport_security: "max-age=631138519", 
      x_content_type_options: "nosniff", 
      x_download_options: "noopen", 
      x_frame_options: "sameorigin", 
      x_permitted_cross_domain_policies: "none", 
      x_xss_protection: "1; mode=block"
    ]
  ]  

  def validate(options) do
    if options[:warn_only] && validate_boolean(options[:warn_only])  do
      validate_options(options) 
    else 
      validate_options!(options) 
    end  
  end
  
  defp validate_options!(options = []) do
    {:ok, options}
  end
  
  defp validate_options!(options) when is_list(options) do
    case validate_options(options) do
      {:ok, options} -> {:ok, options}
      {:error, msg} -> raise ArgumentError, message: msg  
    end
  end  
  
  defp validate_options!(_), do: {:error, @error_msg}

  defp validate_options(options) when is_list(options) do
    case validate_option_keys(options) do
      nil   ->  {:ok, options}
      false ->  {:error, @error_msg}
      true  ->  
        case validate_option_values(options) do
          nil   ->  {:error, @error_msg}
          false ->  {:error, @error_msg}
          true  ->  {:ok, options}
        end
    end
  end
  
  defp validate_options(_), do: {:error, @error_msg}

  defp validate_option_keys(options) do
    List.foldl( Keyword.keys(options), true, fn (key,acc) -> List.keymember?(@secure_config,key,0) && acc end) 
  end

  defp validate_option_values(options) do
  List.foldl( Keyword.keys(options), true, fn (key,acc) ->  validate_option_value(options, key) && acc end) 
  end

  defp validate_option_value(options, key) do
    if(key != :config) do List.keymember?(@secure_config,key,0) && validate_boolean(options[key]) 
    else List.foldl( Keyword.keys(options[:config]), true, fn (key,acc) -> List.keymember?(@secure_config[:config],key,0) && acc end) end
  end

  def validate_boolean(v) when v |> is_boolean do
    true
  end

  def validate_boolean(_) do
    false
  end
end
  
