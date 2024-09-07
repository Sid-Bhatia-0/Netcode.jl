function get_serialized_size(value::Integer)
    if !isbits(value)
        error("Currently only isbits Integer values are supported for serialization")
    else
        return sizeof(value)
    end
end

get_serialized_size(value::Vector{UInt8}) = length(value)

get_serialized_size(value::Union{Sockets.IPv4, Sockets.IPv6}) = get_serialized_size(value.host)

get_serialized_size(value::Union{Sockets.InetAddr{Sockets.IPv4}, Sockets.InetAddr{Sockets.IPv6}}) = get_serialized_size(value.host) + sizeof(value.port)

function get_serialized_size(netcode_address::NetcodeAddress)
    @assert is_valid(netcode_address)

    n = 0

    n += get_serialized_size(netcode_address.address_type)

    if netcode_address.address_type == ADDRESS_TYPE_IPV4
        n += get_serialized_size(netcode_address.host_ipv4)
    else
        n += get_serialized_size(netcode_address.host_ipv6)
    end

    n += get_serialized_size(netcode_address.port)

    return n
end

get_serialized_size(value::Vector{NetcodeAddress}) = sum(get_serialized_size, value)

get_serialized_size_fields(value) = sum(get_serialized_size(getfield(value, i)) for i in 1:fieldcount(typeof(value)))

get_serialized_size(::PrivateConnectToken) = SIZE_OF_ENCRYPTED_PRIVATE_CONNECT_TOKEN_DATA - SIZE_OF_HMAC

get_serialized_size(value::PrivateConnectTokenAssociatedData) = get_serialized_size_fields(value)

get_serialized_size(value::ChallengeTokenMessage) = SIZE_OF_CHALLENGE_TOKEN - SIZE_OF_HMAC

get_serialized_size(value::ConnectionPacketAssociatedData) = get_serialized_size_fields(value)

get_serialized_size(packet::AbstractPacket) = get_serialized_size_fields(packet)

get_serialized_size(::ConnectTokenPacket) = SIZE_OF_CONNECT_TOKEN_PACKET

function get_serialized_size(value::CompactUnsignedInteger)
    x = value.value
    num_bits_required = get_serialized_size(x) * 8 - leading_zeros(x)
    if num_bits_required == 0
        return 1
    else
        return fld1(num_bits_required, 8)
    end
end

get_serialized_size(value::ExtendedUnsignedInteger) = value.extended_serialized_size

function get_serialized_data(value)
    data = zeros(UInt8, get_serialized_size(value))

    io = IOBuffer(data, write = true, maxsize = length(data))

    num_bytes_written = write(io, value)

    @assert num_bytes_written == length(data) "$(num_bytes_written), $(length(data))"

    return data
end

function Base.write(io::IO, netcode_address::NetcodeAddress)
    @assert is_valid(netcode_address)

    n = 0

    n += write(io, netcode_address.address_type)

    if netcode_address.address_type == ADDRESS_TYPE_IPV4
        n += write(io, netcode_address.host_ipv4)
    else
        n += write(io, netcode_address.host_ipv6)
    end

    n += write(io, netcode_address.port)

    return n
end

function Base.write(io::IO, netcode_addresses::Vector{NetcodeAddress})
    n = 0

    for netcode_address in netcode_addresses
        n += write(io, netcode_address)
    end

    return n
end

function write_fields(io::IO, value)
    n = 0

    for i in 1:fieldcount(typeof(value))
        n += write(io, getfield(value, i))
    end

    return n
end

function write_fields_and_padding(io::IO, value)
    n = write_fields(io, value)

    serialized_size = get_serialized_size(value)

    padding_size = serialized_size - n

    for i in 1 : padding_size
        n += write(io, UInt8(0))
    end

    return n
end

Base.write(io::IO, private_connect_token::PrivateConnectToken) = write_fields_and_padding(io, private_connect_token)

Base.write(io::IO, private_connect_token_associated_data::PrivateConnectTokenAssociatedData) = write_fields(io, private_connect_token_associated_data)

Base.write(io::IO, challenge_token_message::ChallengeTokenMessage) = write_fields_and_padding(io, challenge_token_message)

Base.write(io::IO, value::ConnectionPacketAssociatedData) = write_fields(io, value)

Base.write(io::IO, packet::AbstractPacket) = write_fields(io, packet)

Base.write(io::IO, packet::ConnectTokenPacket) = write_fields_and_padding(io, packet)

function Base.write(io::IO, value::CompactUnsignedInteger)
    n = 0

    serialized_size = get_serialized_size(value)
    x = value.value

    for i in 1:serialized_size
        n += write(io, UInt8(x & 0xff))
        x = x >> 8
    end

    @assert n == serialized_size

    return n
end

function Base.write(io::IO, value::ExtendedUnsignedInteger)
    n = 0

    x = value.value

    x_serialized_size = get_serialized_size(x)
    extended_serialized_size = value.extended_serialized_size

    @assert extended_serialized_size >= x_serialized_size

    n += write(io, x)

    for i in 1 : extended_serialized_size - x_serialized_size
        n += write(io, UInt8(0))
    end

    @assert n == extended_serialized_size "$(n), $(extended_serialized_size)"

    return n
end

function try_read(io::IO, ::Type{NetcodeAddress})
    address_type = read(io, TYPE_OF_ADDRESS_TYPE)

    if address_type == ADDRESS_TYPE_IPV4
        host_ipv4 = read(io, TYPE_OF_IPV4_HOST)
        host_ipv6 = zero(TYPE_OF_IPV6_HOST)
    elseif address_type == ADDRESS_TYPE_IPV6
        host_ipv4 = zero(TYPE_OF_IPV4_HOST)
        host_ipv6 = read(io, TYPE_OF_IPV6_HOST)
    else
        return nothing
    end

    port = read(io, TYPE_OF_PORT)

    return NetcodeAddress(address_type, host_ipv4, host_ipv6, port)
end

function try_read(io::IO, ::Type{ConnectTokenPacket}, expected_protocol_id)
    netcode_version_info = read(io, SIZE_OF_NETCODE_VERSION_INFO)
    if netcode_version_info != NETCODE_VERSION_INFO
        return nothing
    end

    protocol_id = read(io, TYPE_OF_PROTOCOL_ID)
    if protocol_id != expected_protocol_id
        return nothing
    end

    create_timestamp = read(io, TYPE_OF_TIMESTAMP)
    expire_timestamp = read(io, TYPE_OF_TIMESTAMP)
    if expire_timestamp < create_timestamp
        return nothing
    end

    nonce = read(io, SIZE_OF_NONCE)

    encrypted_private_connect_token_data = read(io, SIZE_OF_ENCRYPTED_PRIVATE_CONNECT_TOKEN_DATA)

    timeout_seconds = read(io, TYPE_OF_TIMEOUT_SECONDS)

    num_server_addresses = read(io, TYPE_OF_NUM_SERVER_ADDRESSES)
    if !(1 <= num_server_addresses <= MAX_NUM_SERVER_ADDRESSES)
        return nothing
    end

    netcode_addresses = NetcodeAddress[]

    for i in 1:num_server_addresses
        netcode_address = try_read(io, NetcodeAddress)
        if !isnothing(netcode_address)
            push!(netcode_addresses, netcode_address)
        else
            return nothing
        end
    end

    client_to_server_key = read(io, SIZE_OF_KEY)

    server_to_client_key = read(io, SIZE_OF_KEY)

    while !eof(io)
        x = read(io, UInt8)
        if x != 0
            return nothing
        end
    end

    return ConnectTokenPacket(
        netcode_version_info,
        protocol_id,
        create_timestamp,
        expire_timestamp,
        nonce,
        encrypted_private_connect_token_data,
        timeout_seconds,
        num_server_addresses,
        netcode_addresses,
        client_to_server_key,
        server_to_client_key,
    )
end

function try_read(io::IO, ::Type{ConnectionRequestPacket}, expected_protocol_id, frame_start_time)
    packet_prefix = read(io, TYPE_OF_PACKET_PREFIX)

    packet_type = get_packet_type(packet_prefix)
    if packet_type != PACKET_TYPE_CONNECTION_REQUEST_PACKET
        return nothing
    end

    netcode_version_info = read(io, SIZE_OF_NETCODE_VERSION_INFO)
    if netcode_version_info != NETCODE_VERSION_INFO
        return nothing
    end

    protocol_id = read(io, TYPE_OF_PROTOCOL_ID)
    if protocol_id != expected_protocol_id
        return nothing
    end

    expire_timestamp = read(io, TYPE_OF_TIMESTAMP)
    if expire_timestamp <= frame_start_time
        return nothing
    end

    nonce = read(io, SIZE_OF_NONCE)

    encrypted_private_connect_token_data = read(io, SIZE_OF_ENCRYPTED_PRIVATE_CONNECT_TOKEN_DATA)

    return ConnectionRequestPacket(
        packet_prefix,
        netcode_version_info,
        protocol_id,
        expire_timestamp,
        nonce,
        encrypted_private_connect_token_data,
    )
end

function try_read(io::IO, ::Type{PrivateConnectToken})
    client_id = read(io, TYPE_OF_CLIENT_ID)

    timeout_seconds = read(io, TYPE_OF_TIMEOUT_SECONDS)

    num_server_addresses = read(io, TYPE_OF_NUM_SERVER_ADDRESSES)
    if !(1 <= num_server_addresses <= MAX_NUM_SERVER_ADDRESSES)
        return nothing
    end

    netcode_addresses = NetcodeAddress[]

    for i in 1:num_server_addresses
        netcode_address = try_read(io, NetcodeAddress)
        if !isnothing(netcode_address)
            push!(netcode_addresses, netcode_address)
        else
            return nothing
        end
    end

    client_to_server_key = read(io, SIZE_OF_KEY)

    server_to_client_key = read(io, SIZE_OF_KEY)

    user_data = read(io, SIZE_OF_USER_DATA)

    # TODO(fix): don't read until eof, read only padding size because we can't assume the size of io
    while !eof(io)
        x = read(io, UInt8)
        if x != 0
            return nothing
        end
    end

    return PrivateConnectToken(
        client_id,
        timeout_seconds,
        num_server_addresses,
        netcode_addresses,
        client_to_server_key,
        server_to_client_key,
        user_data,
    )
end

function save_frame_maybe!(replay_manager::ReplayManager)
    if !isnothing(replay_manager.replay_file_save)
        @assert length(replay_manager.debug_info_save.frame_debug_infos) == replay_manager.debug_info_save.frame_debug_infos[end].game_state.frame_number
        Serialization.serialize(replay_manager.io_replay_file_save, replay_manager.debug_info_save.frame_debug_infos[end])
        flush(replay_manager.io_replay_file_save)
    end

    return nothing
end

function load_replay_file!(debug_info_load::DebugInfo, replay_file)
    io = open(replay_file, "r")

    i = 1

    while !eof(io)
        frame_debug_info_load = Serialization.deserialize(io)

        @assert frame_debug_info_load.game_state.frame_number == i

        push!(debug_info_load.frame_debug_infos, frame_debug_info_load)

        i += 1
    end

    close(io)

    return nothing
end

function load_frame!(game_state::GameState, frame_debug_info_load::FrameDebugInfo)
    game_state.game_start_time = frame_debug_info_load.game_state.game_start_time
    game_state.frame_number = frame_debug_info_load.game_state.frame_number
    game_state.frame_start_time = frame_debug_info_load.game_state.frame_start_time
    game_state.target_frame_rate = frame_debug_info_load.game_state.target_frame_rate
    game_state.target_ns_per_frame = frame_debug_info_load.game_state.target_ns_per_frame
    game_state.max_frames = frame_debug_info_load.game_state.max_frames
    game_state.clean_input_string = frame_debug_info_load.game_state.clean_input_string

    return nothing
end

function load_frame!(app_server_state::AppServerState, frame_debug_info_load::FrameDebugInfo)
    app_server_state.protocol_id = frame_debug_info_load.app_server_state.protocol_id
    app_server_state.server_side_shared_key = copy(frame_debug_info_load.app_server_state.server_side_shared_key)
    app_server_state.netcode_address = frame_debug_info_load.app_server_state.netcode_address

    while !isempty(app_server_state.packet_receive_channel)
        take!(app_server_state.packet_receive_channel)
    end

    for (client_netcode_address, data) in frame_debug_info_load.packets_received
        put!(app_server_state.packet_receive_channel, (client_netcode_address, copy(data)))
    end

    app_server_state.room = deepcopy(frame_debug_info_load.app_server_state.room)
    app_server_state.num_occupied_room = frame_debug_info_load.app_server_state.num_occupied_room
    app_server_state.waiting_room = deepcopy(frame_debug_info_load.app_server_state.waiting_room)
    app_server_state.num_occupied_waiting_room = frame_debug_info_load.app_server_state.num_occupied_waiting_room
    app_server_state.used_connect_token_history = deepcopy(frame_debug_info_load.app_server_state.used_connect_token_history)
    app_server_state.packet_sequence_number = frame_debug_info_load.app_server_state.packet_sequence_number
    app_server_state.challenge_token_sequence_number = frame_debug_info_load.app_server_state.challenge_token_sequence_number

    return nothing
end

function load_frame!(client_state::ClientState, frame_debug_info_load::FrameDebugInfo)
    client_state.protocol_id = frame_debug_info_load.client_state.protocol_id

    while !isempty(client_state.packet_receive_channel)
        take!(client_state.packet_receive_channel)
    end

    for (app_server_netcode_address, data) in frame_debug_info_load.packets_received
        put!(client_state.packet_receive_channel, (app_server_netcode_address, copy(data)))
    end

    client_state.state_machine_state = frame_debug_info_load.client_state.state_machine_state
    client_state.connect_token_packet = frame_debug_info_load.client_state.connect_token_packet
    client_state.last_connection_request_packet_sent_frame = frame_debug_info_load.client_state.last_connection_request_packet_sent_frame

    return nothing
end

function load_frame_maybe!(game_state, app_server_state, client_state, replay_manager::ReplayManager)
    if !isnothing(replay_manager.replay_file_load) && !isnothing(replay_manager.frame_number_load_reset)
        frame_debug_info_load = replay_manager.debug_info_load.frame_debug_infos[replay_manager.frame_number_load_reset]

        load_frame!(game_state, frame_debug_info_load)

        if !isnothing(app_server_state)
            load_frame!(app_server_state, frame_debug_info_load)
        end

        if !isnothing(client_state)
            load_frame!(client_state, frame_debug_info_load)
        end

        # resetting and updating debug info save
        empty!(replay_manager.debug_info_save.frame_debug_infos)
        for i in 1 : replay_manager.frame_number_load_reset
            push!(replay_manager.debug_info_save.frame_debug_infos, deepcopy(replay_manager.debug_info_load.frame_debug_infos[i]))
        end

        if !isnothing(replay_manager.replay_file_save)
            close(replay_manager.io_replay_file_save)

            replay_manager.io_replay_file_save = open(replay_manager.replay_file_save, "w")

            for i in 1 : replay_manager.frame_number_load_reset
                Serialization.serialize(replay_manager.io_replay_file_save, replay_manager.debug_info_save.frame_debug_infos[i])
            end

            flush(replay_manager.io_replay_file_save)
        end

        replay_manager.frame_number_load_reset = nothing # you don't want to keep loading the same frame again and again

        Debugger.@bp
    end

    return nothing
end
