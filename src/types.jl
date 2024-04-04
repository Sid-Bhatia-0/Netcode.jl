struct DebugInfo
    frame_end_time_buffer::Vector{Int}
    frame_time_buffer::Vector{Int}
    update_time_theoretical_buffer::Vector{Int}
    update_time_observed_buffer::Vector{Int}
    sleep_time_theoretical_buffer::Vector{Int}
    sleep_time_observed_buffer::Vector{Int}
end

mutable struct GameState
    game_start_time::Int
    frame_number::Int
    target_frame_rate::Int
    target_ns_per_frame::Int
    total_frames::Int
end

struct NetcodeAddress
    address_type::TYPE_OF_ADDRESS_TYPE
    host_ipv4::TYPE_OF_IPV4_HOST
    host_ipv6::TYPE_OF_IPV6_HOST
    port::TYPE_OF_PORT
end

const NULL_NETCODE_ADDRESS = NetcodeAddress(0, 0, 0, 0)

struct ClientSlot
    is_used::Bool
    netcode_address::NetcodeAddress
    client_id::TYPE_OF_CLIENT_ID
end

const NULL_CLIENT_SLOT = ClientSlot(false, NULL_NETCODE_ADDRESS, 0)

struct WaitingClientSlot
    is_used::Bool
    netcode_address::NetcodeAddress
    client_id::TYPE_OF_CLIENT_ID
    last_seen_timestamp::TYPE_OF_TIMESTAMP
    timeout_seconds::TYPE_OF_TIMEOUT_SECONDS
    client_to_server_key::Vector{UInt8}
    server_to_client_key::Vector{UInt8}
end

const NULL_WAITING_CLIENT_SLOT = WaitingClientSlot(false, NULL_NETCODE_ADDRESS, 0, 0, 0, UInt8[], UInt8[])

struct ConnectTokenInfo
    netcode_version_info::Vector{UInt8}
    protocol_id::TYPE_OF_PROTOCOL_ID
    create_timestamp::TYPE_OF_TIMESTAMP
    expire_timestamp::TYPE_OF_TIMESTAMP
    nonce::Vector{UInt8}
    timeout_seconds::TYPE_OF_TIMEOUT_SECONDS
    client_id::TYPE_OF_CLIENT_ID
    netcode_addresses::Vector{NetcodeAddress}
    client_to_server_key::Vector{UInt8}
    server_to_client_key::Vector{UInt8}
    user_data::Vector{UInt8}
    server_side_shared_key::Vector{UInt8}
end

struct PrivateConnectToken
    client_id::TYPE_OF_CLIENT_ID
    timeout_seconds::TYPE_OF_TIMEOUT_SECONDS
    num_server_addresses::TYPE_OF_NUM_SERVER_ADDRESSES
    netcode_addresses::Vector{NetcodeAddress}
    client_to_server_key::Vector{UInt8}
    server_to_client_key::Vector{UInt8}
    user_data::Vector{UInt8}
end

struct PrivateConnectTokenAssociatedData
    netcode_version_info::Vector{UInt8}
    protocol_id::TYPE_OF_PROTOCOL_ID
    expire_timestamp::TYPE_OF_TIMESTAMP
end

struct ConnectTokenSlot
    last_seen_timestamp::TYPE_OF_TIMESTAMP
    hmac::Vector{UInt8} # TODO(perf): can store hash of hmac instead of hmac
    netcode_address::NetcodeAddress
end

const NULL_CONNECT_TOKEN_SLOT = ConnectTokenSlot(0, UInt8[], NULL_NETCODE_ADDRESS)

abstract type AbstractPacket end

struct ConnectTokenPacket <: AbstractPacket
    netcode_version_info::Vector{UInt8}
    protocol_id::TYPE_OF_PROTOCOL_ID
    create_timestamp::TYPE_OF_TIMESTAMP
    expire_timestamp::TYPE_OF_TIMESTAMP
    nonce::Vector{UInt8}
    encrypted_private_connect_token_data::Vector{UInt8}
    timeout_seconds::TYPE_OF_TIMEOUT_SECONDS
    num_server_addresses::TYPE_OF_NUM_SERVER_ADDRESSES
    netcode_addresses::Vector{NetcodeAddress}
    client_to_server_key::Vector{UInt8}
    server_to_client_key::Vector{UInt8}
end

const NULL_CONNECT_TOKEN_PACKET = ConnectTokenPacket(UInt8[], 0, 0, 0, UInt8[], UInt8[], 0, 0, NetcodeAddress[], UInt8[], UInt8[])

struct ConnectionRequestPacket <: AbstractPacket
    packet_prefix::TYPE_OF_PACKET_PREFIX
    netcode_version_info::Vector{UInt8}
    protocol_id::TYPE_OF_PROTOCOL_ID
    expire_timestamp::TYPE_OF_TIMESTAMP
    nonce::Vector{UInt8}
    encrypted_private_connect_token_data::Vector{UInt8}
end

struct CompactUnsignedInteger
    value::TYPE_OF_MAX_SEQUENCE_NUMBER
end

struct AppServerState
    protocol_id::TYPE_OF_PROTOCOL_ID
    server_side_shared_key::Vector{UInt8}
    netcode_address::NetcodeAddress
    socket::Sockets.UDPSocket
    packet_receive_channel::Channel{Tuple{NetcodeAddress, Vector{UInt8}}}
    packet_send_channel::Channel{Tuple{NetcodeAddress, Vector{UInt8}}}
    room::Vector{ClientSlot}
    waiting_room::Vector{WaitingClientSlot}
    used_connect_token_history::Vector{ConnectTokenSlot}
end

mutable struct ClientState
    protocol_id::TYPE_OF_PROTOCOL_ID
    socket::Sockets.UDPSocket
    packet_receive_channel::Channel{Tuple{NetcodeAddress, Vector{UInt8}}}
    packet_send_channel::Channel{Tuple{NetcodeAddress, Vector{UInt8}}}
    state_machine_state::Int
    received_connect_token_packet::Bool
    connect_token_packet::ConnectTokenPacket
end
