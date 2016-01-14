# This file is responsible for configuring your application
# and its dependencies with the aid of the Mix.Config module.
use Mix.Config

# This configuration is loaded before any dependency and is restricted
# to this project. If another project depends on this project, this
# file won't be loaded nor affect the parent project. For this reason,
# if you want to provide default values for your application for
# 3rd-party users, it should be done in your "mix.exs" file.

# You can configure for your application as:
#
#     config :secure_headers, key: :value
#
# And access this configuration in your application as:
#
#     Application.get_env(:secure_headers, :key)
#
# Or configure a 3rd-party app:
#
#     config :logger, level: :info
#

# It is also possible to import configuration files, relative to this
# directory. For example, you can emulate configuration per environment
# by uncommenting the line below and defining dev.exs, test.exs and such.
# Configuration from the imported file will override the ones defined
# here (which is why it is important to import them last).
#
#import_config "#{Mix.env}.exs"
config :secure_headers, SecureHeaders,
    secure_headers: [
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