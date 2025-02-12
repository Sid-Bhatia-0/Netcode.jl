function setup_packet_receive_channel_task(channel, socket)
    task = errormonitor(
        @async while true
            host_port, data = Sockets.recvfrom(socket)
            put!(channel, (NetcodeAddress(host_port), data))
        end
    )

    return task
end

function set_frame_start_time!(game_state)
    if game_state.frame_number == 1
        game_state.game_start_time = round(TYPE_OF_TIMESTAMP, time() * 10 ^ 9)
        game_state.reference_time_ns = time_ns()
        game_state.frame_start_time = game_state.game_start_time
    else
        game_state.frame_start_time = game_state.game_start_time + get_time_since_reference_time_ns(game_state.reference_time_ns)
    end
end

function replay_frame_start_time_maybe!(game_state)
    if !isnothing(REPLAY_MANAGER.replay_file_load) && REPLAY_MANAGER.is_replay_input
        frame_debug_info_load = REPLAY_MANAGER.debug_info_load.frame_debug_infos[game_state.frame_number]

        @assert game_state.frame_number == frame_debug_info_load.game_state.frame_number

        game_state.frame_start_time = frame_debug_info_load.game_state.frame_start_time
    end

    return nothing
end

function append_frame_debug_info_to_debug_info_save(frame_debug_info, game_state)
    push!(REPLAY_MANAGER.debug_info_save.frame_debug_infos, frame_debug_info)
    @assert length(REPLAY_MANAGER.debug_info_save.frame_debug_infos) == game_state.frame_number

    return nothing
end

function set_raw_input_string!(game_state)
    game_state.raw_input_string = get_raw_input_string()
    return nothing
end

function set_clean_input_string!(game_state)
    game_state.clean_input_string = get_clean_input_string(game_state.raw_input_string)
    return nothing
end

function log_periodic_progress(game_state)
    if mod1(game_state.frame_number, game_state.target_frame_rate) == game_state.target_frame_rate
        @info "Progress" game_state.frame_number
    end

    return nothing
end

function replay_clean_input_string_maybe!(game_state)
    if !isnothing(REPLAY_MANAGER.replay_file_load) && REPLAY_MANAGER.is_replay_input
        frame_debug_info_load = REPLAY_MANAGER.debug_info_load.frame_debug_infos[game_state.frame_number]

        @assert game_state.frame_number == frame_debug_info_load.game_state.frame_number

        game_state.clean_input_string = frame_debug_info_load.game_state.clean_input_string
    end

    return nothing
end

function replay_packet_receive_channel_maybe!(host_state, game_state)
    if !isnothing(REPLAY_MANAGER.replay_file_load) && REPLAY_MANAGER.is_replay_input
        frame_debug_info_load = REPLAY_MANAGER.debug_info_load.frame_debug_infos[game_state.frame_number]

        @assert game_state.frame_number == frame_debug_info_load.game_state.frame_number

        while !isempty(host_state.packet_receive_channel)
            take!(host_state.packet_receive_channel)
        end

        for (netcode_address, data) in frame_debug_info_load.packets_received
            put!(host_state.packet_receive_channel, (netcode_address, copy(data)))
        end
    end

    return nothing
end

function set_previous_frame_time(game_state)
    if game_state.frame_number > 1
        REPLAY_MANAGER.debug_info_save.frame_debug_infos[game_state.frame_number - 1].frame_time = game_state.frame_start_time - REPLAY_MANAGER.debug_info_save.frame_debug_infos[game_state.frame_number - 1].game_state.frame_start_time
    end

    return nothing
end

function receive_and_handle_packets!(host_state, game_state)
    while !isempty(host_state.packet_receive_channel)
        sender_netcode_address, data = take!(host_state.packet_receive_channel)
        @info "Packet received:" sender_netcode_address length(data) game_state.frame_number

        frame_debug_info = REPLAY_MANAGER.debug_info_save.frame_debug_infos[game_state.frame_number]
        push!(frame_debug_info.packets_received, (sender_netcode_address, copy(data)))

        handle_packet!(host_state, sender_netcode_address, data, game_state.frame_number, game_state.frame_start_time)
    end

    return nothing
end

function deepcopy_frame_debug_info(game_state)
    REPLAY_MANAGER.debug_info_save.frame_debug_infos[game_state.frame_number] = deepcopy(REPLAY_MANAGER.debug_info_save.frame_debug_infos[game_state.frame_number])

    return nothing
end

function clean_up!(app_server_state, game_state)
    num_cleaned_up_waiting_room = clean_up!(app_server_state.waiting_room, game_state.frame_number, game_state.target_frame_rate)
    app_server_state.num_occupied_waiting_room -= num_cleaned_up_waiting_room

    return nothing
end

function increment_frame_number!(game_state)
    game_state.frame_number = game_state.frame_number + 1
    return nothing
end

function close_io_replay_file_save_maybe()
    if !isnothing(REPLAY_MANAGER.io_replay_file_save)
        close(REPLAY_MANAGER.io_replay_file_save)
    end

    return nothing
end

function get_frame_debug_info()
    frame_debug_info = REPLAY_MANAGER.debug_info_save.frame_debug_infos[end]

    @assert length(REPLAY_MANAGER.debug_info_save.frame_debug_infos) == frame_debug_info.game_state.frame_number

    return frame_debug_info
end

function send_challenges(app_server_state, game_state)
    frame_debug_info = get_frame_debug_info()

    for (i, waiting_client_slot) in enumerate(app_server_state.waiting_room)
        if waiting_client_slot.is_used
            if game_state.frame_number - waiting_client_slot.last_challenge_sent_frame > (app_server_state.challenge_delay * game_state.target_frame_rate) ÷ 10 ^ 9
                challenge_token_info = ChallengeTokenInfo(app_server_state.challenge_token_sequence_number, waiting_client_slot.client_id, waiting_client_slot.user_data, app_server_state.challenge_token_key)
                app_server_state.challenge_token_sequence_number += 1

                encrypted_challenge_token_data = encrypt(challenge_token_info)
                challenge_packet_info = ChallengePacketInfo(challenge_token_info.challenge_token_sequence_number, encrypted_challenge_token_data)
                challenge_packet_content = get_netcode_serialized_data(challenge_packet_info)

                connection_packet_info = ConnectionPacketInfo(app_server_state.protocol_id, PACKET_TYPE_CONNECTION_CHALLENGE_PACKET, app_server_state.packet_sequence_number, challenge_packet_content, waiting_client_slot.server_to_client_key)

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

    return nothing
end

function request_connect_token_maybe!(client_state, game_state)
    if client_state.state_machine_state == CLIENT_STATE_DISCONNECTED && game_state.frame_number == client_state.connect_token_request_frame
        if !(!isnothing(REPLAY_MANAGER.replay_file_load) && REPLAY_MANAGER.is_replay_input)
            errormonitor(@async client_state.connect_token_request_response = HTTP.get(client_state.auth_server_url))
        end
        @info "Connect token requested" game_state.frame_number
    end

    return nothing
end

function receive_and_process_connect_token_maybe!(client_state, game_state)
    if !isnothing(REPLAY_MANAGER.replay_file_load) && REPLAY_MANAGER.is_replay_input
        frame_debug_info_load = REPLAY_MANAGER.debug_info_load.frame_debug_infos[game_state.frame_number]

        @assert game_state.frame_number == frame_debug_info_load.game_state.frame_number

        client_state.connect_token_request_response = frame_debug_info_load.connect_token_request_response
    end

    # process connect token if received
    if client_state.state_machine_state == CLIENT_STATE_DISCONNECTED && !isnothing(client_state.connect_token_request_response)
        @info "Connect token received" game_state.frame_number

        frame_debug_info = REPLAY_MANAGER.debug_info_save.frame_debug_infos[game_state.frame_number]

        frame_debug_info.connect_token_request_response = deepcopy(client_state.connect_token_request_response)

        if length(client_state.connect_token_request_response.body) != SIZE_OF_CONNECT_TOKEN_PACKET
            client_state.state_machine_state = CLIENT_STATE_INVALID_CONNECT_TOKEN
            error("Connect token invalid: unexpected `packet_size`")
        end

        connect_token_packet = netcode_deserialize(IOBuffer(client_state.connect_token_request_response.body), ConnectTokenPacket, client_state.protocol_id)
        if isnothing(connect_token_packet)
            client_state.state_machine_state = CLIENT_STATE_INVALID_CONNECT_TOKEN
            error("Connect token invalid: `netcode_deserialize` returned `nothing`")
        else
            client_state.connect_token_packet = connect_token_packet
            client_state.state_machine_state = CLIENT_STATE_SENDING_CONNECTION_REQUEST
            client_state.connect_token_request_response = nothing

            @info "Connect token validated" game_state.frame_number
        end
    end

    return nothing
end

function expire_connect_token_maybe!(client_state, game_state)
    if client_state.state_machine_state == CLIENT_STATE_SENDING_CONNECTION_REQUEST && (game_state.frame_start_time >= client_state.connect_token_packet.expire_timestamp * 10 ^ 9) # in the state CLIENT_STATE_SENDING_CONNECTION_REQUEST, client_state.connect_token_packet will never be nothing (otherwise something is wrong and the code better crash)
        @info "Connect token expired" game_state.frame_number
        client_state.connect_token_packet = nothing
        client_state.state_machine_state = CLIENT_STATE_CONNECT_TOKEN_EXPIRED
    end

    return nothing
end

function send_connection_request_packet_maybe!(client_state, game_state)
    if client_state.state_machine_state == CLIENT_STATE_SENDING_CONNECTION_REQUEST && (game_state.frame_number - client_state.last_connection_request_packet_sent_frame > (client_state.connection_request_packet_wait_time * game_state.target_frame_rate) ÷ 10 ^ 9)
        connection_request_packet = ConnectionRequestPacket(client_state.connect_token_packet) # in the state CLIENT_STATE_SENDING_CONNECTION_REQUEST, client_state.connect_token_packet will never be nothing (otherwise something is wrong and the code better crash)

        data = get_netcode_serialized_data(connection_request_packet)

        app_server_netcode_address = first(client_state.connect_token_packet.netcode_addresses)

        app_server_inet_address = get_inetaddr(app_server_netcode_address)
        if !(!isnothing(REPLAY_MANAGER.replay_file_load) && REPLAY_MANAGER.is_replay_input)
            Sockets.send(client_state.socket, app_server_inet_address.host, app_server_inet_address.port, data)
        end

        packet_size = length(data)
        packet_prefix = get_packet_prefix(data)
        packet_type = get_packet_type(packet_prefix)
        @info "Packet sent" game_state.frame_number packet_size packet_prefix packet_type
        frame_debug_info = REPLAY_MANAGER.debug_info_save.frame_debug_infos[game_state.frame_number]
        push!(frame_debug_info.packets_sent, (app_server_inet_address, copy(data)))

        client_state.last_connection_request_packet_sent_frame = game_state.frame_number
    end

    return nothing
end

function handle_packet!(app_server_state::AppServerState, client_netcode_address, data, frame_number, frame_start_time)
    packet_size = length(data)

    if packet_size < 18
        @info "Packet ignored: `packet_size` is too small" packet_size
        return nothing
    end

    packet_prefix = get_packet_prefix(data)
    packet_type = get_packet_type(packet_prefix)

    if packet_type > MAX_PACKET_TYPE
        @info "Packet ignored: invalid `packet_type`" packet_type
        return nothing
    end

    if packet_type == PACKET_TYPE_CONNECTION_REQUEST_PACKET
        if packet_size != SIZE_OF_CONNECTION_REQUEST_PACKET
            @info "Packet ignored: unexpected `packet_size`" packet_size SIZE_OF_CONNECTION_REQUEST_PACKET
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
        num_bytes_of_sequence_number = get_num_bytes_of_sequence_number(packet_prefix)

        if !(num_bytes_of_sequence_number in 1:sizeof(TYPE_OF_MAX_SEQUENCE_NUMBER))
            @info "Packet ignored: `num_bytes_of_sequence_number` not in range" num_bytes_of_sequence_number 1:sizeof(TYPE_OF_MAX_SEQUENCE_NUMBER)
            return nothing
        end

        if packet_size < 1 + num_bytes_of_sequence_number + 16
            @info "Packet ignored: `packet_size` < 1 + `num_bytes_of_sequence_number` + 16" packet_size num_bytes_of_sequence_number
            return nothing
        end

        size_of_packet_content = packet_size - 1 - num_bytes_of_sequence_number - SIZE_OF_HMAC

        if packet_type == PACKET_TYPE_CONNECTION_CHALLENGE_RESPONSE_PACKET
            if size_of_packet_content != SIZE_OF_CONNECTION_CHALLENGE_RESPONSE_PACKET_CONTENT
                @info "Packet ignored: unexpected `size_of_packet_content`" size_of_packet_content SIZE_OF_CONNECTION_CHALLENGE_RESPONSE_PACKET_CONTENT
                return nothing
            end
        elseif packet_type == PACKET_TYPE_CONNECTION_KEEP_ALIVE_PACKET
            if size_of_packet_content != SIZE_OF_CONNECTION_KEEP_ALIVE_PACKET_CONTENT
                @info "Packet ignored: unexpected `size_of_packet_content`" size_of_packet_content SIZE_OF_CONNECTION_KEEP_ALIVE_PACKET_CONTENT
                return nothing
            end
        elseif packet_type == PACKET_TYPE_CONNECTION_PAYLOAD_PACKET
            if !(size_of_packet_content in 1:MAX_SIZE_OF_CONNECTION_PAYLOAD_PACKET_CONTENT)
                @info "Packet ignored: `size_of_packet_content` not in range" size_of_packet_content 1:MAX_SIZE_OF_CONNECTION_PAYLOAD_PACKET_CONTENT
                return nothing
            end
        elseif packet_type == PACKET_TYPE_CONNECTION_DISCONNECT_PACKET
            if size_of_packet_content != SIZE_OF_CONNECTION_DISCONNECT_PACKET_CONTENT
                @info "Packet ignored: unexpected `size_of_packet_content`" size_of_packet_content SIZE_OF_CONNECTION_DISCONNECT_PACKET_CONTENT
                return nothing
            end
        end

        @info "Packet ignored: yet to implement handling of `packet_type`" packet_type
        return nothing
    end
end

function handle_packet!(client_state::ClientState, server_netcode_address, data, frame_number, frame_start_time)
    packet_size = length(data)

    if packet_size < 18
        @info "Packet ignored: `packet_size` is too small" packet_size
        return nothing
    end

    packet_prefix = get_packet_prefix(data)
    packet_type = get_packet_type(packet_prefix)

    if packet_type > MAX_PACKET_TYPE
        @info "Packet ignored: invalid `packet_type`" packet_type
        return nothing
    end

    num_bytes_of_sequence_number = get_num_bytes_of_sequence_number(packet_prefix)

    if !(num_bytes_of_sequence_number in 1:sizeof(TYPE_OF_MAX_SEQUENCE_NUMBER))
        @info "Packet ignored: `num_bytes_of_sequence_number` not in range" num_bytes_of_sequence_number 1:sizeof(TYPE_OF_MAX_SEQUENCE_NUMBER)
        return nothing
    end

    if packet_size < 1 + num_bytes_of_sequence_number + 16
        @info "Packet ignored: `packet_size` < 1 + `num_bytes_of_sequence_number` + 16" packet_size num_bytes_of_sequence_number
        return nothing
    end

    size_of_packet_content = packet_size - 1 - num_bytes_of_sequence_number - SIZE_OF_HMAC

    if packet_type == PACKET_TYPE_CONNECTION_DENIED_PACKET
        if size_of_packet_content != SIZE_OF_CONNECTION_DENIED_PACKET_CONTENT
            @info "Packet ignored: unexpected `size_of_packet_content`" size_of_packet_content SIZE_OF_CONNECTION_DENIED_PACKET_CONTENT
            return nothing
        end
    elseif packet_type == PACKET_TYPE_CONNECTION_CHALLENGE_PACKET
        if size_of_packet_content != SIZE_OF_CONNECTION_CHALLENGE_PACKET_CONTENT
            @info "Packet ignored: unexpected `size_of_packet_content`" size_of_packet_content SIZE_OF_CONNECTION_CHALLENGE_PACKET_CONTENT
            return nothing
        end
    elseif packet_type == PACKET_TYPE_CONNECTION_KEEP_ALIVE_PACKET
        if size_of_packet_content != SIZE_OF_CONNECTION_KEEP_ALIVE_PACKET_CONTENT
            @info "Packet ignored: unexpected `size_of_packet_content`" size_of_packet_content SIZE_OF_CONNECTION_KEEP_ALIVE_PACKET_CONTENT
            return nothing
        end
    elseif packet_type == PACKET_TYPE_CONNECTION_PAYLOAD_PACKET
        if !(size_of_packet_content in 1:MAX_SIZE_OF_CONNECTION_PAYLOAD_PACKET_CONTENT)
            @info "Packet ignored: `size_of_packet_content` not in range" size_of_packet_content 1:MAX_SIZE_OF_CONNECTION_PAYLOAD_PACKET_CONTENT
            return nothing
        end
    elseif packet_type == PACKET_TYPE_CONNECTION_DISCONNECT_PACKET
        if size_of_packet_content != SIZE_OF_CONNECTION_DISCONNECT_PACKET_CONTENT
            @info "Packet ignored: unexpected `size_of_packet_content`" size_of_packet_content SIZE_OF_CONNECTION_DISCONNECT_PACKET_CONTENT
            return nothing
        end
    end

    @info "Packet ignored: yet to implement handling of `packet_type`" packet_type
    return nothing
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

    app_server_state = AppServerState(protocol_id, server_side_shared_key, app_server_inet_address, packet_receive_channel_size, room_size, waiting_room_size, used_connect_token_history_size, challenge_delay, challenge_token_key)
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
        set_frame_start_time!(game_state)
        replay_frame_start_time_maybe!(game_state)

        reset!(frame_debug_info)
        append_frame_debug_info_to_debug_info_save(frame_debug_info, game_state)

        log_periodic_progress(game_state)

        set_raw_input_string!(game_state)

        if game_state.raw_input_string == "p"
            Debugger.@bp
        elseif game_state.raw_input_string == "q"
            break
        end

        set_clean_input_string!(game_state)
        replay_clean_input_string_maybe!(game_state)

        replay_packet_receive_channel_maybe!(app_server_state, game_state)

        set_previous_frame_time(game_state)

        clean_up!(app_server_state, game_state)

        receive_and_handle_packets!(app_server_state, game_state)

        send_challenges(app_server_state, game_state)

        simulate_update!(game_state)

        sleep_to_achieve_target_frame_rate!(game_state)

        deepcopy_frame_debug_info(game_state)

        save_frame_maybe!(REPLAY_MANAGER)
        load_frame_maybe!(game_state, app_server_state, client_state, REPLAY_MANAGER)

        if game_state.frame_number >= game_state.max_frames
            break
        end

        increment_frame_number!(game_state)
    end

    close_io_replay_file_save_maybe()

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

    client_state = ClientState(protocol_id, packet_receive_channel_size, auth_server_url, connect_token_request_frame, connection_request_packet_wait_time)
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

    while true
        set_frame_start_time!(game_state)
        replay_frame_start_time_maybe!(game_state)

        reset!(frame_debug_info)
        append_frame_debug_info_to_debug_info_save(frame_debug_info, game_state)

        log_periodic_progress(game_state)

        set_raw_input_string!(game_state)

        if game_state.raw_input_string == "p"
            Debugger.@bp
        elseif game_state.raw_input_string == "q"
            break
        end

        set_clean_input_string!(game_state)
        replay_clean_input_string_maybe!(game_state)

        replay_packet_receive_channel_maybe!(client_state, game_state)

        set_previous_frame_time(game_state)

        receive_and_handle_packets!(client_state, game_state)

        request_connect_token_maybe!(client_state, game_state)

        receive_and_process_connect_token_maybe!(client_state, game_state)

        expire_connect_token_maybe!(client_state, game_state)

        send_connection_request_packet_maybe!(client_state, game_state)

        simulate_update!(game_state)

        sleep_to_achieve_target_frame_rate!(game_state)

        deepcopy_frame_debug_info(game_state)

        save_frame_maybe!(REPLAY_MANAGER)
        load_frame_maybe!(game_state, app_server_state, client_state, REPLAY_MANAGER)

        if game_state.frame_number >= game_state.max_frames
            break
        end

        increment_frame_number!(game_state)
    end

    close_io_replay_file_save_maybe()

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
                    create_timestamp = round(TYPE_OF_TIMESTAMP, time())
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
