import Netcode

if length(ARGS) == 0
    @info "Empty run"
elseif length(ARGS) == 1
    if ARGS[1] == "--app_server"
        @info "Running as app_server"

        Netcode.test_app_server()
    elseif ARGS[1] == "--auth_server"
        @info "Running as auth_server"

        Netcode.test_auth_server()
    elseif ARGS[1] == "--client"
        @info "Running as client"

        Netcode.test_client()
    else
        error("Unknown command line argument $(ARGS[1])")
    end
else
    error("Invalid command line argument structure")
end
