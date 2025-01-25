function setup_packet_receive_channel_task(channel, socket)
    task = errormonitor(
        @async while true
            host_port, data = Sockets.recvfrom(socket)
            put!(channel, (NetcodeAddress(host_port), data))
        end
    )

    return task
end

function handle_packet!(app_server_state::AppServerState, client_netcode_address, data, frame_number, frame_start_time)
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

        connection_request_packet = netcode_deserialize(io, ConnectionRequestPacket, app_server_state.protocol_id, frame_start_time)
        if isnothing(connection_request_packet)
            @info "Packet ignored: `netcode_deserialize` returned `nothing`"
            return nothing
        end

        private_connect_token = try_decrypt(connection_request_packet, app_server_state.server_side_shared_key)
        if isnothing(private_connect_token)
            @info "Packet ignored: `try_decrypt` returned `nothing`"
            return nothing
        end

        if !(app_server_state.netcode_address in private_connect_token.netcode_addresses)
            @info "Packet ignored: `netcode_address` not found in `private_connect_token.netcode_addresses`"
            return nothing
        end

        if is_client_already_connected(app_server_state.room, client_netcode_address, private_connect_token.client_id)
            @info "Packet ignored: `is_client_already_connected` returned `true`"
            return nothing
        end

        hmac_view = @view connection_request_packet.encrypted_private_connect_token_data[end - SIZE_OF_HMAC + 1 : end]
        hmac_hash = hash(hmac_view)
        connect_token_slot = ConnectTokenSlot(frame_number, hmac_hash, client_netcode_address)

        if !try_add!(app_server_state.used_connect_token_history, connect_token_slot)
            @info "Packet ignored: connect token already used by another `client_id` or `netcode_address`"
            return nothing
        end

        if app_server_state.num_occupied_room == length(app_server_state.room)
            @info "Packet ignored: no empty client slots available"
            return nothing
        end

        waiting_client_slot = WaitingClientSlot(true, client_netcode_address, private_connect_token.client_id, private_connect_token.user_data, frame_number, 0, private_connect_token.timeout_seconds, private_connect_token.client_to_server_key, private_connect_token.server_to_client_key)

        is_waiting_client_added = try_add!(app_server_state.waiting_room, waiting_client_slot)

        if is_waiting_client_added
            app_server_state.num_occupied_waiting_room += 1
            @info "Packet accepted: client added to `waiting_room`"
        else
            @info "Packet ignored: no empty slots available in `waiting_room`"
            return nothing
        end

        return nothing
    else
        @info "Packet ignored: unknown `packet_type`"
        return nothing
    end
end

function start_app_server(test_config)
    protocol_id = test_config.protocol_id
    server_side_shared_key = test_config.server_side_shared_key
    app_server_inet_address = test_config.app_server_address
    packet_receive_channel_size = test_config.packet_receive_channel_size
    room_size = test_config.room_size
    waiting_room_size = test_config.waiting_room_size
    used_connect_token_history_size = test_config.used_connect_token_history_size
    target_frame_rate = test_config.target_frame_rate
    max_frames = test_config.max_frames
    challenge_delay = test_config.challenge_delay
    challenge_token_key = test_config.challenge_token_key

    app_server_state = AppServerState(protocol_id, server_side_shared_key, app_server_inet_address, packet_receive_channel_size, room_size, waiting_room_size, used_connect_token_history_size)
    client_state = nothing

    @info "Server started listening"

    Sockets.bind(app_server_state.socket, app_server_inet_address.host, app_server_inet_address.port)

    setup_packet_receive_channel_task(app_server_state.packet_receive_channel, app_server_state.socket)

    game_state = GameState(target_frame_rate, max_frames)

    frame_debug_info = FrameDebugInfo(game_state, app_server_state, nothing)

    reset!(
        REPLAY_MANAGER,
        replay_file_save = test_config.replay_file_save_server,
        replay_file_load = test_config.replay_file_load_server,
        frame_number_load_reset = test_config.frame_number_load_reset_server,
    )

    while true
        if !isnothing(REPLAY_MANAGER.replay_file_load) && REPLAY_MANAGER.is_replay_input
            frame_debug_info_load = REPLAY_MANAGER.debug_info_load.frame_debug_infos[game_state.frame_number]

            @assert game_state.frame_number == frame_debug_info_load.game_state.frame_number

            game_state.frame_start_time = frame_debug_info_load.game_state.frame_start_time
        else
            game_state.frame_start_time = time_ns()
        end

        reset!(frame_debug_info)

        if game_state.frame_number == 1
            game_state.game_start_time = game_state.frame_start_time
        end

        push!(REPLAY_MANAGER.debug_info_save.frame_debug_infos, frame_debug_info)
        @assert length(REPLAY_MANAGER.debug_info_save.frame_debug_infos) == game_state.frame_number

        if mod1(game_state.frame_number, target_frame_rate) == target_frame_rate
            @info "Progress" game_state.frame_number
        end

        game_state.raw_input_string = get_raw_input_string()

        if game_state.raw_input_string == "p"
            Debugger.@bp
        elseif game_state.raw_input_string == "q"
            break
        end

        if !isnothing(REPLAY_MANAGER.replay_file_load) && REPLAY_MANAGER.is_replay_input
            frame_debug_info_load = REPLAY_MANAGER.debug_info_load.frame_debug_infos[game_state.frame_number]

            @assert game_state.frame_number == frame_debug_info_load.game_state.frame_number

            game_state.clean_input_string = frame_debug_info_load.game_state.clean_input_string

            while !isempty(app_server_state.packet_receive_channel)
                take!(app_server_state.packet_receive_channel)
            end

            for (netcode_address, data) in frame_debug_info_load.packets_received
                put!(app_server_state.packet_receive_channel, (netcode_address, copy(data)))
            end
        else
            game_state.clean_input_string = get_clean_input_string(game_state.raw_input_string)
        end

        if game_state.frame_number > 1
            REPLAY_MANAGER.debug_info_save.frame_debug_infos[game_state.frame_number - 1].frame_time = game_state.frame_start_time - REPLAY_MANAGER.debug_info_save.frame_debug_infos[game_state.frame_number - 1].game_state.frame_start_time
        end

        num_cleaned_up_waiting_room = clean_up!(app_server_state.waiting_room, game_state.frame_number, game_state.target_frame_rate)
        app_server_state.num_occupied_waiting_room -= num_cleaned_up_waiting_room

        while !isempty(app_server_state.packet_receive_channel)
            client_netcode_address, data = take!(app_server_state.packet_receive_channel)
            push!(frame_debug_info.packets_received, (client_netcode_address, copy(data)))

            handle_packet!(app_server_state, client_netcode_address, data, game_state.frame_number, game_state.frame_start_time)
        end

        for (i, waiting_client_slot) in enumerate(app_server_state.waiting_room)
            if waiting_client_slot.is_used
                if game_state.frame_number - waiting_client_slot.last_challenge_sent_frame > (challenge_delay * game_state.target_frame_rate) ÷ 10 ^ 9
                    challenge_token_info = ChallengeTokenInfo(app_server_state.challenge_token_sequence_number, waiting_client_slot.client_id, waiting_client_slot.user_data, challenge_token_key)
                    app_server_state.challenge_token_sequence_number += 1

                    encrypted_challenge_token_data = encrypt(challenge_token_info)

                    connection_packet_info = ConnectionPacketInfo(app_server_state.protocol_id, PACKET_TYPE_CONNECTION_CHALLENGE_PACKET, app_server_state.packet_sequence_number, encrypted_challenge_token_data, waiting_client_slot.server_to_client_key)

                    encrypted_packet_data = encrypt(connection_packet_info)

                    packet_prefix = generate_packet_prefix(PACKET_TYPE_CONNECTION_CHALLENGE_PACKET, app_server_state.packet_sequence_number)

                    connection_packet = ConnectionPacket(packet_prefix, CompactUnsignedInteger(app_server_state.packet_sequence_number), encrypted_packet_data)

                    data = get_netcode_serialized_data(connection_packet)

                    inet_address = get_inetaddr(waiting_client_slot.netcode_address)
                    Sockets.send(app_server_state.socket, inet_address.host, inet_address.port, data)

                    packet_size = length(data)
                    packet_prefix = get_packet_prefix(data)
                    packet_type = get_packet_type(packet_prefix)
                    packet_sequence_number = app_server_state.packet_sequence_number
                    @info "Packet sent" game_state.frame_number packet_size packet_prefix packet_type packet_sequence_number
                    push!(frame_debug_info.packets_sent, (inet_address, copy(data)))

                    app_server_state.packet_sequence_number += 1

                    app_server_state.waiting_room[i] = Accessors.@set waiting_client_slot.last_challenge_sent_frame = game_state.frame_number
                end
            end
        end

        simulate_update!(game_state)

        sleep_to_achieve_target_frame_rate!(game_state)

        REPLAY_MANAGER.debug_info_save.frame_debug_infos[game_state.frame_number] = deepcopy(REPLAY_MANAGER.debug_info_save.frame_debug_infos[game_state.frame_number])

        save_frame_maybe!(REPLAY_MANAGER)
        load_frame_maybe!(game_state, app_server_state, client_state, REPLAY_MANAGER)

        if game_state.frame_number >= game_state.max_frames
            break
        end

        game_state.frame_number = game_state.frame_number + 1
    end

    if !isnothing(REPLAY_MANAGER.io_replay_file_save)
        close(REPLAY_MANAGER.io_replay_file_save)
    end

    summarize_debug_info(REPLAY_MANAGER.debug_info_save)

    return nothing
end

function start_client(test_config)
    auth_server_address = test_config.auth_server_address
    username = test_config.client_username
    password = test_config.client_password
    protocol_id = test_config.protocol_id
    packet_receive_channel_size = test_config.packet_receive_channel_size
    target_frame_rate = test_config.target_frame_rate
    max_frames = test_config.max_frames
    connect_token_request_frame = test_config.connect_token_request_frame
    connection_request_packet_wait_time = test_config.connection_request_packet_wait_time

    hashed_password = bytes2hex(SHA.sha3_256(password))
    auth_server_url = "http://" * username * ":" * hashed_password * "@" * string(auth_server_address.host) * ":" * string(auth_server_address.port)

    client_state = ClientState(protocol_id, packet_receive_channel_size)
    app_server_state = nothing

    setup_packet_receive_channel_task(client_state.packet_receive_channel, client_state.socket)

    game_state = GameState(target_frame_rate, max_frames)

    frame_debug_info = FrameDebugInfo(game_state, nothing, client_state)

    reset!(
        REPLAY_MANAGER,
        replay_file_save = test_config.replay_file_save_client,
        replay_file_load = test_config.replay_file_load_client,
        frame_number_load_reset = test_config.frame_number_load_reset_client,
    )

    connect_token_request_response = nothing

    while true
        if !isnothing(REPLAY_MANAGER.replay_file_load) && REPLAY_MANAGER.is_replay_input
            frame_debug_info_load = REPLAY_MANAGER.debug_info_load.frame_debug_infos[game_state.frame_number]

            @assert game_state.frame_number == frame_debug_info_load.game_state.frame_number

            game_state.frame_start_time = frame_debug_info_load.game_state.frame_start_time
        else
            game_state.frame_start_time = time_ns()
        end

        reset!(frame_debug_info)

        if game_state.frame_number == 1
            game_state.game_start_time = game_state.frame_start_time
        end

        push!(REPLAY_MANAGER.debug_info_save.frame_debug_infos, frame_debug_info)
        @assert length(REPLAY_MANAGER.debug_info_save.frame_debug_infos) == game_state.frame_number

        if mod1(game_state.frame_number, target_frame_rate) == target_frame_rate
            @info "Progress" game_state.frame_number
        end

        game_state.raw_input_string = get_raw_input_string()

        if game_state.raw_input_string == "p"
            Debugger.@bp
        elseif game_state.raw_input_string == "q"
            break
        end

        if !isnothing(REPLAY_MANAGER.replay_file_load) && REPLAY_MANAGER.is_replay_input
            frame_debug_info_load = REPLAY_MANAGER.debug_info_load.frame_debug_infos[game_state.frame_number]

            @assert game_state.frame_number == frame_debug_info_load.game_state.frame_number

            game_state.clean_input_string = frame_debug_info_load.game_state.clean_input_string

            while !isempty(client_state.packet_receive_channel)
                take!(client_state.packet_receive_channel)
            end

            for (netcode_address, data) in frame_debug_info_load.packets_received
                put!(client_state.packet_receive_channel, (netcode_address, copy(data)))
            end
        else
            game_state.clean_input_string = get_clean_input_string(game_state.raw_input_string)
        end

        if game_state.frame_number > 1
            REPLAY_MANAGER.debug_info_save.frame_debug_infos[game_state.frame_number - 1].frame_time = game_state.frame_start_time - REPLAY_MANAGER.debug_info_save.frame_debug_infos[game_state.frame_number - 1].game_state.frame_start_time
        end

        # request connect token
        if client_state.state_machine_state == CLIENT_STATE_DISCONNECTED && game_state.frame_number == connect_token_request_frame
            errormonitor(@async connect_token_request_response = HTTP.get(auth_server_url))
            @info "Connect token requested" game_state.frame_number
        end

        # process connect token when received
        if client_state.state_machine_state == CLIENT_STATE_DISCONNECTED && !isnothing(connect_token_request_response)
            @info "Connect token received" game_state.frame_number

            if length(connect_token_request_response.body) != SIZE_OF_CONNECT_TOKEN_PACKET
                client_state.state_machine_state = CLIENT_STATE_INVALID_CONNECT_TOKEN
                error("Connect token invalid: unexpected `packet_size`")
            end

            connect_token_packet = netcode_deserialize(IOBuffer(connect_token_request_response.body), ConnectTokenPacket, protocol_id)
            if isnothing(connect_token_packet)
                client_state.state_machine_state = CLIENT_STATE_INVALID_CONNECT_TOKEN
                error("Connect token invalid: `netcode_deserialize` returned `nothing`")
            else
                client_state.connect_token_packet = connect_token_packet
                client_state.state_machine_state = CLIENT_STATE_SENDING_CONNECTION_REQUEST
            end

            @info "Connect token validated" game_state.frame_number
        end

        # invalidate connect token when expired
        if client_state.state_machine_state == CLIENT_STATE_SENDING_CONNECTION_REQUEST && (game_state.frame_start_time >= client_state.connect_token_packet.expire_timestamp)
            @info "Connect token expired" game_state.frame_number
            client_state.connect_token_packet = nothing
            client_state.state_machine_state = CLIENT_STATE_CONNECT_TOKEN_EXPIRED
        end

        # send connection request packet when possible
        if client_state.state_machine_state == CLIENT_STATE_SENDING_CONNECTION_REQUEST && (game_state.frame_number - client_state.last_connection_request_packet_sent_frame > (connection_request_packet_wait_time * game_state.target_frame_rate) ÷ 10 ^ 9)
            connection_request_packet = ConnectionRequestPacket(client_state.connect_token_packet)

            data = get_netcode_serialized_data(connection_request_packet)

            app_server_netcode_address = first(client_state.connect_token_packet.netcode_addresses)

            app_server_inet_address = get_inetaddr(app_server_netcode_address)
            Sockets.send(client_state.socket, app_server_inet_address.host, app_server_inet_address.port, data)

            packet_size = length(data)
            packet_prefix = get_packet_prefix(data)
            packet_type = get_packet_type(packet_prefix)
            @info "Packet sent" game_state.frame_number packet_size packet_prefix packet_type
            push!(frame_debug_info.packets_sent, (app_server_inet_address, copy(data)))

            client_state.last_connection_request_packet_sent_frame = game_state.frame_number
        end

        simulate_update!(game_state)

        sleep_to_achieve_target_frame_rate!(game_state)

        REPLAY_MANAGER.debug_info_save.frame_debug_infos[game_state.frame_number] = deepcopy(REPLAY_MANAGER.debug_info_save.frame_debug_infos[game_state.frame_number])

        save_frame_maybe!(REPLAY_MANAGER)
        load_frame_maybe!(game_state, app_server_state, client_state, REPLAY_MANAGER)

        if game_state.frame_number >= game_state.max_frames
            break
        end

        game_state.frame_number = game_state.frame_number + 1
    end

    if !isnothing(REPLAY_MANAGER.io_replay_file_save)
        close(REPLAY_MANAGER.io_replay_file_save)
    end

    summarize_debug_info(REPLAY_MANAGER.debug_info_save)

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
                    create_timestamp = time_ns()
                    connect_token_info = ConnectTokenInfo(create_timestamp, protocol_id, timeout_seconds, connect_token_expire_seconds, server_side_shared_key, app_server_addresses, i)

                    connect_token_packet = ConnectTokenPacket(connect_token_info)

                    data = get_netcode_serialized_data(connect_token_packet)

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

function start_auth_server(test_config)
    auth_server_address = test_config.auth_server_address
    df_user_data = test_config.user_data
    protocol_id = test_config.protocol_id
    timeout_seconds = test_config.timeout_seconds
    connect_token_expire_seconds = test_config.connect_token_expire_seconds
    server_side_shared_key = test_config.server_side_shared_key
    app_server_addresses = test_config.app_server_addresses

    HTTP.serve(request -> auth_handler(request, df_user_data, protocol_id, timeout_seconds, connect_token_expire_seconds, server_side_shared_key, app_server_addresses), auth_server_address.host, auth_server_address.port)
end
