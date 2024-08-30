import Netcode

if length(ARGS) == 1
    if ARGS[1] == "--app_server"
        Netcode.test_app_server()
    elseif ARGS[1] == "--auth_server"
        Netcode.test_auth_server()
    elseif ARGS[1] == "--client"
        Netcode.test_client()
    else
        error("Unknown command line argument $(ARGS[1])")
    end
elseif length(ARGS) > 1
    error("Invalid command line argument structure")
end
