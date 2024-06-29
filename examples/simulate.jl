import Netcode

debug_info = nothing

if length(ARGS) == 0
    @info "Empty run"
elseif length(ARGS) == 1
    if ARGS[1] == "--app_server"
        @info "Running as app_server" Netcode.APP_SERVER_ADDRESS Netcode.AUTH_SERVER_ADDRESS

        debug_info = Netcode.test_app_server()
    elseif ARGS[1] == "--auth_server"
        @info "Running as auth_server" Netcode.APP_SERVER_ADDRESS Netcode.AUTH_SERVER_ADDRESS

        debug_info = Netcode.test_auth_server()
    else
        error("Unknown command line argument $(ARGS[1])")
    end
elseif length(ARGS) == 3
    if ARGS[1] == "--client"
        @info "Running as client" Netcode.APP_SERVER_ADDRESS Netcode.AUTH_SERVER_ADDRESS

        client_username = ARGS[2]
        client_password = ARGS[3]

        debug_info = Netcode.start_client(Netcode.AUTH_SERVER_ADDRESS, client_username, client_password, Netcode.PROTOCOL_ID, Netcode.PACKET_RECEIVE_CHANNEL_SIZE, Netcode.TARGET_FRAME_RATE, Netcode.TOTAL_FRAMES, Netcode.CONNECT_TOKEN_REQUEST_FRAME, Netcode.CONNECTION_REQUEST_PACKET_WAIT_TIME, save_debug_info_file = Netcode.CLIENT_SAVE_DEBUG_INFO_FILE)
    else
        error("Unknown command line argument $(ARGS[1])")
    end
else
    error("Invalid command line argument structure")
end
