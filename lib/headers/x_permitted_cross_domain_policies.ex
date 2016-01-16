defmodule SecureHeaders.XPermittedCrossDomainPolicies do

  @valid_header ~r/\A(ALL\z|NONE\z|MASTER-ONLY\z|BY-FTP-FILENAME\z|BY-CONTENT-TYPE\z|])/i
  
  @error_msg "Invalid configuration for x-permitted-cross-domain-policies"
  
  def validate(options) when is_list(options) do
    case Keyword.has_key?(options, :config) do 
      false -> {:ok, options}
      true  -> 
    	case Keyword.has_key?(options[:config], :x_permitted_cross_domain_policies) do
      	# No x-permitted-cross-domain configuration found - return config
      	false	-> {:ok, options}
        true	->
       	case validate_config(options[:config][:x_permitted_cross_domain_policies]) do
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

  defp validate_config(_), do: false
end
