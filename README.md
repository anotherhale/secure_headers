# SecureHeaders

This Plug will automatically apply several security headers to the Plug.Conn response. By design SecureHeaders will attempt to apply the most strict security policy.  Although, security headers are configurable and are validated to avoid misconfiguration.   

The supported security headers include:
  
- Content Security Policy (CSP) - Helps detect/prevent XSS, mixed-content, and other classes of attack.  [CSP 2 Specification](http://www.w3.org/TR/CSP2/)
- HTTP Strict Transport Security (HSTS) - Ensures the browser never visits the http version of a website. Protects from SSLStrip/Firesheep attacks.  [HSTS Specification](https://tools.ietf.org/html/rfc6797)
- X-Frame-Options (XFO) - Prevents your content from being framed and potentially clickjacked. [X-Frame-Options draft](https://tools.ietf.org/html/draft-ietf-websec-x-frame-options-02)
- X-XSS-Protection - [Cross site scripting heuristic filter for IE/Chrome](http://msdn.microsoft.com/en-us/library/dd565647\(v=vs.85\).aspx)
- X-Content-Type-Options - [Prevent content type sniffing](http://msdn.microsoft.com/en-us/library/ie/gg622941\(v=vs.85\).aspx)
- X-Download-Options - [Prevent file downloads opening](http://msdn.microsoft.com/en-us/library/ie/jj542450(v=vs.85).aspx)
- X-Permitted-Cross-Domain-Policies - [Restrict Adobe Flash Player's access to data](https://www.adobe.com/devnet/adobe-media-server/articles/cross-domain-xml-for-streaming.html)
- Public Key Pinning - Pin certificate fingerprints in the browser to prevent man-in-the-middle attacks due to compromised Certificate Authorities. [Public Key Pinning  Specification](https://tools.ietf.org/html/rfc7469)

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed as:

  1. Add secure_headers to your list of dependencies in `mix.exs`:

        def deps do
          [{:secure_headers, "~> 0.1.0"}]
        end

  2. Ensure secure_headers is started before your application:

        def application do
          [applications: [:secure_headers]]
        end
        
  3. Add the plug to your application, e.g., to a pipeline in a [Phoenix](http://www.phoenixframework.org/)
router.   SecureHeaders by design defaults to a strict security policy.  If no opts are supplied it uses
the following secure configuration:

```elixir
config secure_headers:, SecureHeaders, 
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
```

```elixir
defmodule SecurePhoenixApp.SecureRouter do
  use SecurePhoenixApp.Web, :router
  
  pipeline :browser do
    plug :accepts, ["html", "text"]
    plug :fetch_session
    plug :fetch_flash
    plug :protect_from_forgery
    plug SecureHeaders
  end

  scope "/", HelloPhoenix do
    pipe_through :browser # Use the default browser stack

    get "/", PageController, :index
  end
end    
```

```elixir
defmodule SecurePhoenixApp.SecureController do
  use SecurePhoenixApp.Web, :controller
  alias Plug.Conn.Status

  def index(conn, _params) do
    conn
    |> put_status(Status.code :ok)
    |> text """
    SecureHeaders secure configuration:
    
    Content Security Policy (CSP):         #{conn.assigns[:content_security_policy]}
    HTTP Strict Transport Security (HSTS): #{conn.assigns[:strict_transport_security]}
    X-Content-Type-Options:                #{conn.assigns[:x_content_type_options]}
    X-Download-Options:                    #{conn.assigns[:x_download_options]}
    X-Frame-Options (XFO):                 #{conn.assigns[:x_frame_options]}
    X-Permitted-Cross-Domain-Policies:     #{conn.assigns[:x_permitted_cross_domain_policies]}  
    X-XSS-Protection:                      #{conn.assigns[:x_xss_protection]}
    Public Key Pinning:                    #{conn.assigns[:http_public_key_pins]}     

    """
    end
end
```

Configuration values can be overridden in the application environment.  By default they will be merged with the default secure header configuration.

Order of merge resolution

First - config provided in-line to the plug

```elixir
    plug SecureHeaders secure_headers: [config: [x_xss_protection: "1; mode=block"]]
```

Second - config in Application environment

```elixir
# filename: dev.exs

use Mix.Config

config secure_headers:, SecureHeaders, 
    config: [
      content_security_policy: "default-src 'self';" , 
      strict_transport_security: "max-age=631138519", 
      x_permitted_cross_domain_policies: "none", 
      x_xss_protection: "0"
    ]
```

Third - default secure config

You can disable merging application environment configuration with the default secure configuration by providing the following option [merge_config: false] to SecureHeaders:

```elixir
defmodule SecurePhoenixApp.SecureRouter do
  use SecurePhoenixApp.Web, :router
  
  pipeline :browser do
    plug :accepts, ["html", "text"]
    plug :fetch_session
    plug :fetch_flash
    plug :protect_from_forgery
    plug SecureHeaders secure_headers: [merge_config: false]
  end

  scope "/", HelloPhoenix do
    pipe_through :browser # Use the default browser stack

    get "/", PageController, :index
  end
end    
```


