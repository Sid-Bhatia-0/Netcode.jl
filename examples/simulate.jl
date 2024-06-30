import Netcode

debug_info = nothing

test_config = Netcode.TestConfig()

Netcode.pprint(test_config)

if length(ARGS) == 0
    @info "Empty run"
elseif length(ARGS) == 1
    if ARGS[1] == "--app_server"
        @info "Running as app_server" test_config.app_server_address test_config.auth_server_address

        debug_info = Netcode.test_app_server(test_config)
    elseif ARGS[1] == "--auth_server"
        @info "Running as auth_server" test_config.app_server_address test_config.auth_server_address

        debug_info = Netcode.test_auth_server(test_config)
    elseif ARGS[1] == "--client"
        @info "Running as client" test_config.app_server_address test_config.auth_server_address

        debug_info = Netcode.test_client(test_config)
    else
        error("Unknown command line argument $(ARGS[1])")
    end
else
    error("Invalid command line argument structure")
end
