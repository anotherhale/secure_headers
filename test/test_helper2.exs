ExUnit.start()

defmodule AppMaker do
	defmacro __using__(options) do
		quote do
			use Plug.Router
			alias Plug.Conn.Status
			plug PlugSecureHeaders, unquote(options)
			plug :match
			plug :dispatch
		end
	end
end
	
defmodule TestApp do
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
	use AppMaker, plug_secure_headers: @secure_config
	get "/" do
		send_resp(conn, Status.code(:ok), "API key: #{conn.assigns[:api_key]}")
	end
end

defmodule CustomTestApp do
	use AppMaker, plug_secure_headers: [ 
		warn_only: false,
    merge: false,
    report_only: false,
    use_secure_config: true,
    config: [
      content_security_policy: "default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self';"]
  ]
	get "/" do
		send_resp(conn, Status.code(:ok), "API key: #{conn.assigns[:api_key]}")
	end
end

defmodule CustomTestAppMergeConfigFalse do
	use AppMaker, plug_secure_headers: [ 
		warn_only: false,
    merge: false,
    report_only: false,
    use_secure_config: true,
    config: [
      content_security_policy: "default-src 'none';"]
  ]
	get "/" do
		send_resp(conn, Status.code(:ok), "API key: #{conn.assigns[:api_key]}")
	end
end

defmodule CustomTestAppMergeConfigTrue do
	use AppMaker, plug_secure_headers: [ 
		warn_only: false,
    merge: true,
    report_only: false,
    use_secure_config: true,
    config: [
      content_security_policy: "default-src 'none';"]
  ]
	get "/" do
		send_resp(conn, Status.code(:ok), "API key: #{conn.assigns[:api_key]}")
	end
end

defmodule SecureAppRouter do
  use Plug.Router
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
	plug PlugSecureHeaders, @secure_config
  plug :match
  plug :dispatch

  get "/" do
    send_resp(conn, 200, "default config")
  end

  match _ do
    send_resp(conn, 404, "oops")
  end
end

defmodule CustomAppRouter do
  use Plug.Router
  @custom_config [
    report_only: true,
    config: [ 
      content_security_policy: "default-src 'none';", 
      strict_transport_security: "max-age=631138519", 
      x_permitted_cross_domain_policies: "none", 
      x_xss_protection: "1; mode=block"
    ]
  ] 
	plug PlugSecureHeaders, @custom_config
  plug :match
  plug :dispatch

  get "/custom" do
    send_resp(conn, 200, "custom config")
  end

  match _ do
    send_resp(conn, 404, "oops")
  end
end


