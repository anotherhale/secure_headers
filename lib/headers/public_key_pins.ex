defmodule SecureHeaders.PublicKeyPins do

  @valid_header  ~r/^((pin-sha256=\S+)\s*){2,}\s*max-age=\d+(;\s*?includeSubdomains)?(;\s*?report-uri=\S+)?/  
  @error_msg "Invalid configuration for public-key-pins"
  @secure_config [
  	pin_sha256: "",
  	max_age: 5184000,
  	includesubdomains: false,
  	report_uri: ""
  ]

  def validate(options) when is_list(options) do
    case Keyword.has_key?(options, :config) do 
      false -> {:ok, options}
      true  -> 
    	case Keyword.has_key?(options[:config], :http_public_key_pins) do
      	# No http-public-key-pins configuration found - return config
      	false	-> {:ok, options}
    	  true	->
   	    case validate_config(options[:config][:http_public_key_pins]) do
        	false -> {:error, @error_msg}
      	  true  -> {:ok, options}
        end
      end 
    end
  end  
  
  def validate(_),  do: {:error, @error_msg}

  defp validate_config(config) when is_bitstring(config) do
  	Regex.match?( @valid_header, config)
  end

  defp validate_config(config) do
  # TODO implement keyword list to string function
  	false
  end
end
