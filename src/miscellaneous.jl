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
        if used_connect_token_history[i].hmac == connect_token_slot.hmac
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

function try_add!(room::Vector{ClientSlot}, client_slot::ClientSlot)
    for i in axes(room, 1)
        if !room[i].is_used
            room[i] = client_slot
            return true
        end
    end

    return false
end

get_packet_prefix(packet_data::Vector{UInt8})::TYPE_OF_PACKET_PREFIX = first(packet_data)

get_packet_type(packet_prefix::TYPE_OF_PACKET_PREFIX)::TYPE_OF_PACKET_TYPE = packet_prefix & 0xf
