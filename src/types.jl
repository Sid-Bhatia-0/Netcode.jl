struct DebugInfo
    frame_end_time_buffer::Vector{Int}
    frame_time_buffer::Vector{Int}
    update_time_theoretical_buffer::Vector{Int}
    update_time_observed_buffer::Vector{Int}
    sleep_time_theoretical_buffer::Vector{Int}
    sleep_time_observed_buffer::Vector{Int}
end

mutable struct GameState
    reference_time::Int
    frame_number::Int
    target_frame_rate::Int
    target_ns_per_frame::Int
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

struct ConnectionRequestPacket <: AbstractPacket
    packet_type::TYPE_OF_PACKET_TYPE
    netcode_version_info::Vector{UInt8}
    protocol_id::TYPE_OF_PROTOCOL_ID
    expire_timestamp::TYPE_OF_TIMESTAMP
    nonce::Vector{UInt8}
    encrypted_private_connect_token_data::Vector{UInt8}
end
