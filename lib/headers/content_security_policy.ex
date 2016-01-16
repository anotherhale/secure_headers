defmodule SecureHeaders.ContentSecurityPolicy do

  @header_name "strict-transport-security"
  @default_value "default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self';"
  @error_msg "Invalid configuration for content-security-policy"

  @directives_1_0 [
    default_src: "none",
    connect_src: "self",
    font_src: "self",
    frame_src: "self",
    img_src: "self",
    media_src: "self",
    object_src: "self",
    sandbox: "",
    script_src: "self",
    style_src: "self",
    report_uri: "",
    report_only: false
  ]

  @directives_2_0 @directives_1_0 ++ [
    base_uri: "",
    child_src: "",
    form_action: "",
    frame_ancestors: "",
    plugin_types: ""
  ]
      
  # All the directives currently under consideration for CSP level 3.
  # https://w3c.github.io/webappsec/specs/CSP2/
  @directives_3_0 @directives_2_0 ++ [
    manifest_src: "",
    reflected_xss: ""
  ]

  # All the directives that are not currently in a formal spec, but have
  # been implemented somewhere.
  @directives_draft [
    block_all_mixed_content: ""
  ]
  
  @all_directives @directives_3_0 ++ @directives_draft
      
  def validate(config) when is_list(config) do
    case Keyword.has_key?(config, :config) do 
      false -> {:ok, config}
      true  -> 
      case Keyword.has_key?(config, :content_security_policy) do
        # No content-security-policy configuration found - return config
        false -> {:ok, config}
        true  ->
        case validate_keys(config[:content_security_policy]) do
          false -> {:error, @error_msg}
          true  ->
          case validate_config(config[:content_security_policy]) do
            false -> {:error, "Invalid configuration value for content security policy"}
            true  -> {:ok, make_string(config)}
          end
        end 
      end
    end
  end  
  
  def validate(_),  do: {:error, @error_msg}
  
  defp validate_keys(config) when is_list(config) do
    List.foldl( Keyword.keys(config), true, fn (key,acc) -> List.keymember?(@all_directives,key,0) && acc end)
  end

  defp validate_keys(_),  do: {:error, @error_msg}
  
  defp validate_config(_) do
    # TODO implement validation of configuration values
    true
  end

  defp make_string(config) do
    csp_config = config[:content_security_policy]
    #
    # ensures default_src is first and report_uri is last
    #
    default_src = "default-src: '" <> csp_config[:default_src] <> "';"
    csp_config = Keyword.delete(csp_config,:default_src)
    
    report_uri = ""
    report_only = false
    if Keyword.has_key?(csp_config, :report_uri) do
      report_uri = " report-uri: '" <>  csp_config[:report_uri] <> "';"
      csp_config = Keyword.delete(csp_config, :report_uri)
    end
    if Keyword.has_key?(csp_config, :report_only) do
      if (csp_config[:report_only] == true) do
        report_only = true
      end
      csp_config = Keyword.delete(csp_config, :report_only)
    end
    csp_str = Enum.reduce(csp_config, default_src, fn ({key, val}, acc) -> acc 
      <> " " <> dasherize(key) 
      <> ": " <> "'" 
      <> val <> "'" 
      <> ";" end) <> report_uri
    case report_only do
      true  -> Keyword.delete(config, :content_security_policy) ++ [content_security_policy_report_only: csp_str]
      false -> Keyword.delete(config, :content_security_policy) ++ [content_security_policy: csp_str]
    end
    
  end
  
  def dasherize(data) when is_atom(data), do: dasherize(Atom.to_string(data))
  
  def dasherize(data), do: String.replace(data, "_", "-")
end
