DebugInfo() = DebugInfo(TYPE_OF_TIMESTAMP[], Int[], Int[], Int[], Int[], Int[])

function GameState(target_frame_rate, total_frames)
    target_ns_per_frame = 1_000_000_000 ÷ target_frame_rate
    return GameState(time_ns(), 1, target_frame_rate, target_ns_per_frame, total_frames)
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

function ConnectTokenInfo(protocol_id, timeout_seconds, connect_token_expire_seconds, server_side_shared_key, app_server_addresses, client_id)
    # TODO: assert conditions on inputs
    create_timestamp = time_ns()
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
    message = get_serialized_data(PrivateConnectToken(connect_token_info))

    associated_data = get_serialized_data(PrivateConnectTokenAssociatedData(connect_token_info))

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

function AppServerState(protocol_id, key, inet_address::Union{Sockets.InetAddr{Sockets.IPv4}, Sockets.InetAddr{Sockets.IPv6}}, packet_receive_channel_size, packet_send_channel_size, room_size, waiting_room_size, used_connect_token_history_size)
    @assert length(key) == SIZE_OF_KEY

    netcode_address = NetcodeAddress(inet_address)

    num_occupied_room = 0

    room = fill(NULL_CLIENT_SLOT, room_size)

    num_occupied_waiting_room = 0

    waiting_room = fill(NULL_WAITING_CLIENT_SLOT, waiting_room_size)

    used_connect_token_history = fill(NULL_CONNECT_TOKEN_SLOT, used_connect_token_history_size)

    socket = Sockets.UDPSocket()

    packet_receive_channel = Channel{Tuple{NetcodeAddress, Vector{UInt8}}}(packet_receive_channel_size)

    packet_send_channel = Channel{Tuple{NetcodeAddress, Vector{UInt8}}}(packet_send_channel_size)

    return AppServerState(
        protocol_id,
        key,
        netcode_address,
        socket,
        packet_receive_channel,
        packet_send_channel,
        room,
        num_occupied_room,
        waiting_room,
        num_occupied_waiting_room,
        used_connect_token_history,
    )
end

function ClientState(protocol_id, packet_receive_channel_size, packet_send_channel_size)
    socket = Sockets.UDPSocket()

    packet_receive_channel = Channel{Tuple{NetcodeAddress, Vector{UInt8}}}(packet_receive_channel_size)

    packet_send_channel = Channel{Tuple{NetcodeAddress, Vector{UInt8}}}(packet_send_channel_size)

    state_machine_state = CLIENT_STATE_DISCONNECTED

    received_connect_token_packet = false

    connect_token_packet = NULL_CONNECT_TOKEN_PACKET

    return ClientState(
        protocol_id,
        socket,
        packet_receive_channel,
        packet_send_channel,
        state_machine_state,
        received_connect_token_packet,
        connect_token_packet,
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
    last_seen_timestamp_oldest = used_connect_token_history[i_oldest].last_seen_timestamp

    for i in axes(used_connect_token_history, 1)
        if used_connect_token_history[i].hmac_hash == connect_token_slot.hmac_hash
            if used_connect_token_history[i].netcode_address != connect_token_slot.netcode_address
                return false
            elseif used_connect_token_history[i].last_seen_timestamp < connect_token_slot.last_seen_timestamp
                used_connect_token_history[i] = connect_token_slot
                return true
            end
        end

        if last_seen_timestamp_oldest > used_connect_token_history[i].last_seen_timestamp
            i_oldest = i
            last_seen_timestamp_oldest = used_connect_token_history[i].last_seen_timestamp
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

function clean_up!(waiting_room::Vector{WaitingClientSlot}, frame_start_time)
    for (i, waiting_client_slot) in enumerate(waiting_room)
        if waiting_client_slot.is_used && (waiting_client_slot.last_seen_timestamp + waiting_client_slot.timeout_seconds * 10 ^ 9 <= frame_start_time)
            waiting_room[i] = Accessors.@set waiting_client_slot.is_used = false
        end
    end

    return nothing
end

get_packet_prefix(packet_data::Vector{UInt8})::TYPE_OF_PACKET_PREFIX = first(packet_data)

get_packet_type(packet_prefix::TYPE_OF_PACKET_PREFIX)::TYPE_OF_PACKET_TYPE = packet_prefix & 0xf
