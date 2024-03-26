import Netcode

if length(ARGS) == 1
    if ARGS[1] == "--app_server"
        @info "Running as app_server" Netcode.APP_SERVER_ADDRESS Netcode.AUTH_SERVER_ADDRESS

        Netcode.start_app_server(Netcode.APP_SERVER_ADDRESS, Netcode.ROOM_SIZE, Netcode.USED_CONNECT_TOKEN_HISTORY_SIZE, Netcode.SERVER_SIDE_SHARED_KEY)

    elseif ARGS[1] == "--auth_server"
        @info "Running as auth_server" Netcode.APP_SERVER_ADDRESS Netcode.AUTH_SERVER_ADDRESS

        Netcode.start_auth_server(Netcode.AUTH_SERVER_ADDRESS, Netcode.USER_DATA, Netcode.PROTOCOL_ID, Netcode.TIMEOUT_SECONDS, Netcode.CONNECT_TOKEN_EXPIRE_SECONDS, Netcode.APP_SERVER_ADDRESSES)

    elseif ARGS[1] == "--client"
        @info "Running as client" Netcode.APP_SERVER_ADDRESS Netcode.AUTH_SERVER_ADDRESS

        Netcode.start_client(Netcode.AUTH_SERVER_ADDRESS, Netcode.CLIENT_USERNAME, Netcode.CLIENT_PASSWORD)

    else
        error("Invalid command line argument $(ARGS[1])")
    end
elseif length(ARGS) > 1
    error("This script accepts at most one command line flag")
end
