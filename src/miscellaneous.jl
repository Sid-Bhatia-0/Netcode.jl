function ReplayManagerTest(; replay_file_save = nothing, replay_file_load = nothing, frame_number_load_reset = nothing)
    if !isnothing(frame_number_load_reset)
        @assert !isnothing(replay_file_load)
    end

    if !isnothing(replay_file_save) && !isnothing(replay_file_load)
        @assert replay_file_save != replay_file_load
    end

    if !isnothing(replay_file_save)
        io_replay_file_save = open(replay_file_save, "w")
    else
        io_replay_file_save = nothing
    end

    debug_info_save = DebugInfoTest(FrameDebugInfoTest[])

    if !isnothing(replay_file_load)
        debug_info_load = load_replay_file(replay_file_load)
        is_replay_input = true

        if !isnothing(frame_number_load_reset)
            @assert frame_number_load_reset in 1 : length(debug_info_load.frame_debug_infos)
        end
    else
        debug_info_load = nothing
        is_replay_input = false
    end

    return ReplayManagerTest(
        replay_file_save,
        replay_file_load,
        io_replay_file_save,
        debug_info_save,
        debug_info_load,
        is_replay_input,
        frame_number_load_reset,
    )
end

function reset!(replay_manager::ReplayManager; replay_file_save = nothing, replay_file_load = nothing, frame_number_load_reset = nothing)
    if !isnothing(frame_number_load_reset)
        @assert !isnothing(replay_file_load)
    end

    if !isnothing(replay_file_save) && !isnothing(replay_file_load)
        @assert replay_file_save != replay_file_load
    end

    if !isnothing(replay_file_save)
        io_replay_file_save = open(replay_file_save, "w")
    else
        io_replay_file_save = nothing
    end

    if !isnothing(replay_file_load)
        debug_info_load = DebugInfo(FrameDebugInfo[])
        load_replay_file!(debug_info_load, replay_file_load)

        is_replay_input = true

        if !isnothing(frame_number_load_reset)
            @assert frame_number_load_reset in 1 : length(debug_info_load.frame_debug_infos)
        end
    else
        debug_info_load = nothing
        is_replay_input = false
    end

    replay_manager.replay_file_save = replay_file_save
    replay_manager.replay_file_load = replay_file_load
    replay_manager.io_replay_file_save = io_replay_file_save
    empty!(replay_manager.debug_info_save.frame_debug_infos)
    replay_manager.debug_info_load = debug_info_load
    replay_manager.is_replay_input = is_replay_input
    replay_manager.frame_number_load_reset = frame_number_load_reset

    return nothing
end

FrameDebugInfo(game_state, app_server_state, client_state) = FrameDebugInfo(game_state, 0, 0, 0, 0, 0, [], [], app_server_state, client_state)

function reset!(frame_debug_info::FrameDebugInfo)
    frame_debug_info.frame_time = 0
    frame_debug_info.update_time_theoretical = 0
    frame_debug_info.update_time_observed = 0
    frame_debug_info.sleep_time_theoretical = 0
    frame_debug_info.sleep_time_observed = 0
    empty!(frame_debug_info.packets_received)
    empty!(frame_debug_info.packets_sent)

    return nothing
end

function GameState(target_frame_rate, max_frames)
    target_ns_per_frame = 1_000_000_000 ÷ target_frame_rate
    return GameState(0, 1, 0, target_frame_rate, target_ns_per_frame, max_frames, "", "")
end

function NetcodeAddress(address::Union{Sockets.InetAddr{Sockets.IPv4}, Sockets.InetAddr{Sockets.IPv6}})
    if address isa Sockets.InetAddr{Sockets.IPv4}
        address_type = ADDRESS_TYPE_IPV4
        host_ipv4 = address.host.host
        host_ipv6 = zero(TYPE_OF_IPV6_HOST)
    else
        address_type = ADDRESS_TYPE_IPV6
        host_ipv4 = zero(TYPE_OF_IPV4_HOST)
        host_ipv6 = address.host.host
    end

    port = address.port

    return NetcodeAddress(address_type, host_ipv4, host_ipv6, port)
end

is_valid(netcode_address::NetcodeAddress) = netcode_address.address_type == ADDRESS_TYPE_IPV4 || netcode_address.address_type == ADDRESS_TYPE_IPV6

function get_inetaddr(netcode_address::NetcodeAddress)
    @assert is_valid(netcode_address)

    if netcode_address.address_type == ADDRESS_TYPE_IPV4
        host = Sockets.IPv4(netcode_address.host_ipv4)
    else
        host = Sockets.IPv6(netcode_address.host_ipv6)
    end

    return Sockets.InetAddr(host, netcode_address.port)
end

function ConnectTokenInfo(create_timestamp, protocol_id, timeout_seconds, connect_token_expire_seconds, server_side_shared_key, app_server_addresses, client_id)
    # TODO: assert conditions on inputs
    expire_timestamp = create_timestamp + connect_token_expire_seconds * 10 ^ 9

    return ConnectTokenInfo(
        NETCODE_VERSION_INFO,
        protocol_id,
        create_timestamp,
        expire_timestamp,
        rand(UInt8, SIZE_OF_NONCE),
        timeout_seconds,
        client_id,
        NetcodeAddress.(app_server_addresses),
        rand(UInt8, SIZE_OF_KEY),
        rand(UInt8, SIZE_OF_KEY),
        rand(UInt8, SIZE_OF_USER_DATA),
        server_side_shared_key,
    )
end

function PrivateConnectToken(connect_token_info::ConnectTokenInfo)
    return PrivateConnectToken(
        connect_token_info.client_id,
        connect_token_info.timeout_seconds,
        length(connect_token_info.netcode_addresses),
        connect_token_info.netcode_addresses,
        connect_token_info.client_to_server_key,
        connect_token_info.server_to_client_key,
        connect_token_info.user_data,
    )
end

function PrivateConnectTokenAssociatedData(connect_token_info::ConnectTokenInfo)
    return PrivateConnectTokenAssociatedData(
        connect_token_info.netcode_version_info,
        connect_token_info.protocol_id,
        connect_token_info.expire_timestamp,
    )
end

function PrivateConnectTokenAssociatedData(connection_request_packet::ConnectionRequestPacket)
    return PrivateConnectTokenAssociatedData(
        connection_request_packet.netcode_version_info,
        connection_request_packet.protocol_id,
        connection_request_packet.expire_timestamp,
    )
end

function ConnectTokenPacket(connect_token_info::ConnectTokenInfo)
    message = get_netcode_serialized_data(PrivateConnectToken(connect_token_info))

    associated_data = get_netcode_serialized_data(PrivateConnectTokenAssociatedData(connect_token_info))

    encrypted_private_connect_token_data = encrypt(message, associated_data, connect_token_info.nonce, connect_token_info.server_side_shared_key)

    return ConnectTokenPacket(
        connect_token_info.netcode_version_info,
        connect_token_info.protocol_id,
        connect_token_info.create_timestamp,
        connect_token_info.expire_timestamp,
        connect_token_info.nonce,
        encrypted_private_connect_token_data,
        connect_token_info.timeout_seconds,
        length(connect_token_info.netcode_addresses),
        connect_token_info.netcode_addresses,
        connect_token_info.client_to_server_key,
        connect_token_info.server_to_client_key,
    )
end

function ConnectionRequestPacket(connect_token_packet::ConnectTokenPacket)
    return ConnectionRequestPacket(
        PACKET_TYPE_CONNECTION_REQUEST_PACKET,
        connect_token_packet.netcode_version_info,
        connect_token_packet.protocol_id,
        connect_token_packet.expire_timestamp,
        connect_token_packet.nonce,
        connect_token_packet.encrypted_private_connect_token_data,
    )
end

function AppServerState(protocol_id, key, inet_address::Union{Sockets.InetAddr{Sockets.IPv4}, Sockets.InetAddr{Sockets.IPv6}}, packet_receive_channel_size, room_size, waiting_room_size, used_connect_token_history_size)
    @assert length(key) == SIZE_OF_KEY

    netcode_address = NetcodeAddress(inet_address)

    num_occupied_room = 0

    room = fill(NULL_CLIENT_SLOT, room_size)

    num_occupied_waiting_room = 0

    waiting_room = fill(NULL_WAITING_CLIENT_SLOT, waiting_room_size)

    used_connect_token_history = fill(NULL_CONNECT_TOKEN_SLOT, used_connect_token_history_size)

    socket = Sockets.UDPSocket()

    packet_receive_channel = Channel{Tuple{NetcodeAddress, Vector{UInt8}}}(packet_receive_channel_size)

    packet_sequence_number = 0

    challenge_token_sequence_number = 0

    return AppServerState(
        protocol_id,
        key,
        netcode_address,
        socket,
        packet_receive_channel,
        room,
        num_occupied_room,
        waiting_room,
        num_occupied_waiting_room,
        used_connect_token_history,
        packet_sequence_number,
        challenge_token_sequence_number,
    )
end

function ClientState(protocol_id, packet_receive_channel_size)
    socket = Sockets.UDPSocket()

    packet_receive_channel = Channel{Tuple{NetcodeAddress, Vector{UInt8}}}(packet_receive_channel_size)

    state_machine_state = CLIENT_STATE_DISCONNECTED

    connect_token_packet = nothing

    last_connection_request_packet_sent_frame = 0

    return ClientState(
        protocol_id,
        socket,
        packet_receive_channel,
        state_machine_state,
        connect_token_packet,
        last_connection_request_packet_sent_frame,
    )
end

function ChallengeTokenMessage(challenge_token_info::ChallengeTokenInfo)
    return ChallengeTokenMessage(
        challenge_token_info.client_id,
        challenge_token_info.user_data,
    )
end

function ConnectionPacketInfo(protocol_id, packet_type, packet_sequence_number, packet_data, server_to_client_key)
    return ConnectionPacketInfo(
        NETCODE_VERSION_INFO,
        protocol_id,
        packet_type,
        packet_sequence_number,
        packet_data,
        server_to_client_key,
    )
end

function ConnectionPacketAssociatedData(connection_packet_info::ConnectionPacketInfo)
    packet_prefix = generate_packet_prefix(connection_packet_info.packet_type, connection_packet_info.packet_sequence_number)

    return ConnectionPacketAssociatedData(
        connection_packet_info.netcode_version_info,
        connection_packet_info.protocol_id,
        packet_prefix,
    )
end

function pprint(x)
    GP.pprint(x)
    println()
    return nothing
end

function is_client_already_connected(room, client_netcode_address, client_id)
    for client_slot in room
        if client_slot.is_used
            if client_slot.netcode_address == client_netcode_address
                @info "client_netcode_address already connected"
                return true
            end

            if client_slot.client_id == client_id
                @info "client_id already connected"
                return true
            end
        end
    end

    return false
end

function try_add!(used_connect_token_history::Vector{ConnectTokenSlot}, connect_token_slot::ConnectTokenSlot)
    i_oldest = 1
    last_seen_frame_oldest = used_connect_token_history[i_oldest].last_seen_frame

    for i in axes(used_connect_token_history, 1)
        if used_connect_token_history[i].hmac_hash == connect_token_slot.hmac_hash
            if used_connect_token_history[i].netcode_address != connect_token_slot.netcode_address
                return false
            elseif used_connect_token_history[i].last_seen_frame < connect_token_slot.last_seen_frame
                used_connect_token_history[i] = connect_token_slot
                return true
            end
        end

        if last_seen_frame_oldest > used_connect_token_history[i].last_seen_frame
            i_oldest = i
            last_seen_frame_oldest = used_connect_token_history[i].last_seen_frame
        end
    end

    used_connect_token_history[i_oldest] = connect_token_slot

    return true
end

function try_add!(room, slot)
    for i in axes(room, 1)
        if !room[i].is_used
            room[i] = slot
            return true
        end
    end

    return false
end

function clean_up!(waiting_room::Vector{WaitingClientSlot}, frame_number, target_frame_rate)
    num_cleaned_up = 0

    for (i, waiting_client_slot) in enumerate(waiting_room)
        if waiting_client_slot.is_used && (waiting_client_slot.last_seen_frame + waiting_client_slot.timeout_seconds * target_frame_rate <= frame_number)
            waiting_room[i] = Accessors.@set waiting_client_slot.is_used = false
            num_cleaned_up += 1
        end
    end

    return num_cleaned_up
end

get_packet_prefix(packet_data::Vector{UInt8})::TYPE_OF_PACKET_PREFIX = first(packet_data)

get_packet_type(packet_prefix::TYPE_OF_PACKET_PREFIX)::TYPE_OF_PACKET_TYPE = packet_prefix & 0xf

generate_packet_prefix(packet_type::TYPE_OF_PACKET_TYPE, packet_sequence_number) = packet_type | convert(TYPE_OF_PACKET_PREFIX, get_netcode_serialized_size(CompactUnsignedInteger(packet_sequence_number)))

function create_logger(name, modules)
    return LE.EarlyFilteredLogger(
        shouldlog_args -> shouldlog_args._module in modules,
        LE.TeeLogger(
            Logging.ConsoleLogger(),
            LE.MinLevelLogger(LE.FileLogger("$(name)_info.log"), Logging.Info),
            LE.MinLevelLogger(LE.FileLogger("$(name)_debug.log"), Logging.Debug),
        ),
    )
end
