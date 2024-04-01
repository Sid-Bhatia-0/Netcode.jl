function setup_packet_receive_channel_task(channel, socket)
    task = errormonitor(
        @async while true
            host_port, data = Sockets.recvfrom(socket)
            put!(channel, (NetcodeAddress(host_port), data))
        end
    )

    return task
end

function setup_packet_send_channel_task(channel, socket)
    task = errormonitor(
        @async while true
            netcode_address, data = take!(channel)
            address = get_inetaddr(netcode_address)
            Sockets.send(socket, address.host, address.port, data)
        end
    )

    return task
end

function handle_packet!(app_server_state, client_netcode_address, data)
    protocol_id = app_server_state.protocol_id
    server_side_shared_key = app_server_state.server_side_shared_key
    app_server_netcode_address = app_server_state.netcode_address
    room = app_server_state.room
    used_connect_token_history = app_server_state.used_connect_token_history

    packet_size = length(data)

    if packet_size == 0
        return nothing
    end

    packet_prefix = get_packet_prefix(data)
    packet_type = get_packet_type(packet_prefix)

    @info "Packet received:" client_netcode_address packet_size packet_prefix packet_type

    if packet_type == PACKET_TYPE_CONNECTION_REQUEST_PACKET
        if packet_size != SIZE_OF_CONNECTION_REQUEST_PACKET
            @info "Packet ignored: unexpected `packet_size`"
            return nothing
        end

        io = IOBuffer(data)

        connection_request_packet = try_read(io, ConnectionRequestPacket, protocol_id)
        if isnothing(connection_request_packet)
            @info "Packet ignored: `try_read` returned `nothing`"
            return nothing
        end

        private_connect_token = try_decrypt(connection_request_packet, server_side_shared_key)
        if isnothing(private_connect_token)
            @info "Packet ignored: `try_decrypt` returned `nothing`"
            return nothing
        end

        if !(app_server_netcode_address in private_connect_token.netcode_addresses)
            @info "Packet ignored: `app_server_netcode_address` not found in `private_connect_token.netcode_addresses`"
            return nothing
        end

        if is_client_already_connected(room, client_netcode_address, private_connect_token.client_id)
            @info "Packet ignored: `is_client_already_connected` returned `true`"
            return nothing
        end

        connect_token_slot = ConnectTokenSlot(time_ns(), connection_request_packet.encrypted_private_connect_token_data[end - SIZE_OF_HMAC + 1 : end], client_netcode_address)

        if !try_add!(used_connect_token_history, connect_token_slot)
            @info "Packet ignored: connect token already used by another `client_id` or `netcode_address`"
            return nothing
        end

        client_slot = ClientSlot(true, client_netcode_address, private_connect_token.client_id)

        is_client_added = try_add!(room, client_slot)

        if is_client_added
            @info "Packet accepted"
        else
            @info "Packet ignored: no empty client slots available"
            return nothing
        end

        return nothing
    else
        @info "Packet ignored: unknown `packet_type`"
        return nothing
    end
end

function start_app_server(protocol_id, server_side_shared_key, app_server_inet_address, packet_receive_channel_size, packet_send_channel_size, room_size, used_connect_token_history_size)
    app_server_state = AppServerState(protocol_id, server_side_shared_key, app_server_inet_address, packet_receive_channel_size, packet_send_channel_size, room_size, used_connect_token_history_size)

    @info "Server started listening"

    Sockets.bind(app_server_state.socket, app_server_inet_address.host, app_server_inet_address.port)

    setup_packet_receive_channel_task(app_server_state.packet_receive_channel, app_server_state.socket)
    setup_packet_send_channel_task(app_server_state.packet_send_channel, app_server_state.socket)

    target_frame_rate = 60
    total_frames = target_frame_rate * 20
    target_ns_per_frame = 1_000_000_000 ÷ target_frame_rate

    debug_info = DebugInfo(Int[], Int[], Int[], Int[], Int[], Int[])
    game_state = GameState(time_ns(), 1, target_frame_rate, target_ns_per_frame)

    while game_state.frame_number <= total_frames
        if mod1(game_state.frame_number, target_frame_rate) == target_frame_rate
            @show game_state.frame_number
        end

        while !isempty(app_server_state.packet_receive_channel)
            @show game_state.frame_number

            client_netcode_address, data = take!(app_server_state.packet_receive_channel)

            handle_packet!(app_server_state, client_netcode_address, data)
        end

        simulate_update!(game_state, debug_info)

        sleep_to_achieve_target_frame_rate!(game_state, debug_info)

        push!(debug_info.frame_end_time_buffer, get_time(game_state.reference_time))
        if game_state.frame_number == 1
            push!(debug_info.frame_time_buffer, first(debug_info.frame_end_time_buffer))
        else
            push!(debug_info.frame_time_buffer, debug_info.frame_end_time_buffer[game_state.frame_number] - debug_info.frame_end_time_buffer[game_state.frame_number - 1])
        end

        game_state.frame_number = game_state.frame_number + 1
    end

    df_debug_info = create_df_debug_info(debug_info)
    display(DF.describe(df_debug_info, :min, :max, :mean, :std))

    return nothing
end

function start_client(auth_server_address, username, password, protocol_id, packet_receive_channel_size, packet_send_channel_size)
    hashed_password = bytes2hex(SHA.sha3_256(password))
    auth_server_url = "http://" * username * ":" * hashed_password * "@" * string(auth_server_address.host) * ":" * string(auth_server_address.port)

    client_state = ClientState(protocol_id, packet_receive_channel_size, packet_send_channel_size)

    setup_packet_receive_channel_task(client_state.packet_receive_channel, client_state.socket)
    setup_packet_send_channel_task(client_state.packet_send_channel, client_state.socket)

    target_frame_rate = 60
    total_frames = target_frame_rate * 20
    target_ns_per_frame = 1_000_000_000 ÷ target_frame_rate

    debug_info = DebugInfo(Int[], Int[], Int[], Int[], Int[], Int[])
    game_state = GameState(time_ns(), 1, target_frame_rate, target_ns_per_frame)

    connect_token_packet = nothing

    while game_state.frame_number <= total_frames
        if !isnothing(connect_token_packet) && client_state.state_machine_state != CLIENT_STATE_CONNECTED
            connection_request_packet = ConnectionRequestPacket(connect_token_packet)

            data = get_serialized_data(connection_request_packet)

            app_server_netcode_address = first(connect_token_packet.netcode_addresses)

            put!(client_state.packet_send_channel, (app_server_netcode_address, data))

            packet_size = length(data)
            packet_prefix = get_packet_prefix(data)
            packet_type = get_packet_type(packet_prefix)

            @info "Packet sent" game_state.frame_number packet_size packet_prefix packet_type

            client_state.state_machine_state = CLIENT_STATE_CONNECTED
        end

        if mod1(game_state.frame_number, target_frame_rate) == target_frame_rate
            @show game_state.frame_number
        end

        if game_state.frame_number == 5 * target_frame_rate
            @info "Connect token requested" game_state.frame_number

            response = HTTP.get(auth_server_url)

            if length(response.body) != SIZE_OF_CONNECT_TOKEN_PACKET
                error("Connect token invalid: unexpected `packet_size`")
            end

            connect_token_packet = try_read(IOBuffer(response.body), ConnectTokenPacket, protocol_id)
            if isnothing(connect_token_packet)
                error("Connect token invalid: `try_read` returned `nothing`")
            end

            @info "Connect token received"
        end

        simulate_update!(game_state, debug_info)

        sleep_to_achieve_target_frame_rate!(game_state, debug_info)

        push!(debug_info.frame_end_time_buffer, get_time(game_state.reference_time))
        if game_state.frame_number == 1
            push!(debug_info.frame_time_buffer, first(debug_info.frame_end_time_buffer))
        else
            push!(debug_info.frame_time_buffer, debug_info.frame_end_time_buffer[game_state.frame_number] - debug_info.frame_end_time_buffer[game_state.frame_number - 1])
        end

        game_state.frame_number = game_state.frame_number + 1
    end

    df_debug_info = create_df_debug_info(debug_info)
    display(DF.describe(df_debug_info, :min, :max, :mean, :std))

    return nothing
end

function auth_handler(request, df_user_data, protocol_id, timeout_seconds, connect_token_expire_seconds, server_side_shared_key, app_server_addresses)
    i = findfirst(x -> x.first == "Authorization", request.headers)

    if isnothing(i)
        return HTTP.Response(400, "ERROR: Authorization not found in header")
    else
        if startswith(request.headers[i].second, "Basic ")
            base_64_encoded_credentials = split(request.headers[i].second)[2]
            base_64_decoded_credentials = String(Base64.base64decode(base_64_encoded_credentials))
            username, hashed_password = split(base_64_decoded_credentials, ':')

            i = findfirst(==(username), df_user_data[!, :username])

            if isnothing(i)
                return HTTP.Response(400, "ERROR: Invalid credentials")
            else
                if bytes2hex(SHA.sha3_256(hashed_password * df_user_data[i, :salt])) == df_user_data[i, :hashed_salted_hashed_password]
                    connect_token_info = ConnectTokenInfo(protocol_id, timeout_seconds, connect_token_expire_seconds, server_side_shared_key, app_server_addresses, i)

                    connect_token_packet = ConnectTokenPacket(connect_token_info)

                    data = get_serialized_data(connect_token_packet)

                    return HTTP.Response(200, data)
                else
                    return HTTP.Response(400, "ERROR: Invalid credentials")
                end
            end
        else
            return HTTP.Response(400, "ERROR: Authorization type must be Basic authorization")
        end
    end
end

start_auth_server(auth_server_address, df_user_data, protocol_id, timeout_seconds, connect_token_expire_seconds, server_side_shared_key, app_server_addresses) = HTTP.serve(request -> auth_handler(request, df_user_data, protocol_id, timeout_seconds, connect_token_expire_seconds, server_side_shared_key, app_server_addresses), auth_server_address.host, auth_server_address.port)
