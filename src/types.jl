mutable struct GameStateTest
    frame_number::Int
    raw_input_string::String
    clean_input_string::String
    max_num_frames::Int
end

mutable struct FrameDebugInfoTest
    game_state::GameStateTest
end

mutable struct DebugInfoTest
    frame_debug_infos::Vector{FrameDebugInfoTest}
end

mutable struct ReplayManager
    replay_file_save::Union{Nothing, String}
    replay_file_load::Union{Nothing, String}
    io_replay_file_save::Union{Nothing, IO}
    debug_info_save::DebugInfoTest
    debug_info_load::Union{Nothing, DebugInfoTest}
    is_replay_input::Union{Nothing, Bool}
    frame_number_load_reset::Union{Nothing, Int}
end

struct TestConfig
    protocol_id::TYPE_OF_PROTOCOL_ID
    rng::Random.AbstractRNG
    server_side_shared_key::Vector{UInt8}
    room_size::Int
    waiting_room_size::Int
    timeout_seconds::TYPE_OF_TIMEOUT_SECONDS
    connect_token_expire_seconds::Int
    auth_server_address::Sockets.InetAddr
    app_server_addresses::Vector{Sockets.InetAddr}
    app_server_address::Sockets.InetAddr
    used_connect_token_history_size::Int
    num_users::Int
    user_data::DF.DataFrame
    packet_receive_channel_size::Int
    target_frame_rate::Int
    total_frames::Int
    connect_token_request_frame::Int
    challenge_delay::Int
    connection_request_packet_wait_time::Int
    challenge_token_key::Vector{UInt8}
    client_save_debug_info_file::Union{Nothing, String}
    server_save_debug_info_file::Union{Nothing, String}
    client_username::String
    client_password::String
end

mutable struct FrameDebugInfo
    frame_number::Int
    frame_start_time::TYPE_OF_TIMESTAMP
    frame_time::Int
    update_time_theoretical::Int
    update_time_observed::Int
    sleep_time_theoretical::Int
    sleep_time_observed::Int
    packets_received::Vector{Any}
    packets_sent::Vector{Any}
end

struct DebugInfo
    frame_debug_infos::Vector{FrameDebugInfo}
end

const DEBUG_INFO = DebugInfo(FrameDebugInfo[])

mutable struct GameState
    game_start_time::TYPE_OF_TIMESTAMP
    frame_number::Int
    frame_start_time::TYPE_OF_TIMESTAMP
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
    user_data::Vector{UInt8}
    last_seen_frame::Int
    last_challenge_sent_frame::Int
    timeout_seconds::TYPE_OF_TIMEOUT_SECONDS
    client_to_server_key::Vector{UInt8}
    server_to_client_key::Vector{UInt8}
end

const NULL_WAITING_CLIENT_SLOT = WaitingClientSlot(false, NULL_NETCODE_ADDRESS, 0, UInt8[], 0, 0, 0, UInt8[], UInt8[])

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

struct ConnectionPacketInfo
    netcode_version_info::Vector{UInt8}
    protocol_id::TYPE_OF_PROTOCOL_ID
    packet_type::TYPE_OF_PACKET_TYPE
    packet_sequence_number::TYPE_OF_MAX_SEQUENCE_NUMBER
    packet_data::Vector{UInt8}
    server_to_client_key::Vector{UInt8}
end

struct ConnectionPacketAssociatedData
    netcode_version_info::Vector{UInt8}
    protocol_id::TYPE_OF_PROTOCOL_ID
    prefix_byte::TYPE_OF_PACKET_PREFIX
end

struct ChallengeTokenInfo
    challenge_token_sequence_number::TYPE_OF_CHALLENGE_TOKEN_SEQUENCE_NUMBER
    client_id::TYPE_OF_CLIENT_ID
    user_data::Vector{UInt8}
    challenge_token_key::Vector{UInt8}
end

struct ChallengeTokenMessage
    client_id::TYPE_OF_CLIENT_ID
    user_data::Vector{UInt8}
end

struct ConnectTokenSlot
    last_seen_frame::Int
    hmac_hash::UInt64
    netcode_address::NetcodeAddress
end

const NULL_CONNECT_TOKEN_SLOT = ConnectTokenSlot(0, 0, NULL_NETCODE_ADDRESS)

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

struct ExtendedUnsignedInteger
    extended_serialized_size::Int
    value::UInt
end

struct ConnectionPacket <: AbstractPacket
    packet_prefix::TYPE_OF_PACKET_PREFIX
    packet_sequence_number::CompactUnsignedInteger
    encrypted_data::Vector{UInt8}
end

mutable struct AppServerState
    protocol_id::TYPE_OF_PROTOCOL_ID
    server_side_shared_key::Vector{UInt8}
    netcode_address::NetcodeAddress
    socket::Sockets.UDPSocket
    packet_receive_channel::Channel{Tuple{NetcodeAddress, Vector{UInt8}}}
    room::Vector{ClientSlot}
    num_occupied_room::Int
    waiting_room::Vector{WaitingClientSlot}
    num_occupied_waiting_room::Int
    used_connect_token_history::Vector{ConnectTokenSlot}
    packet_sequence_number::TYPE_OF_MAX_SEQUENCE_NUMBER
    challenge_token_sequence_number::TYPE_OF_CHALLENGE_TOKEN_SEQUENCE_NUMBER
end

mutable struct ClientState
    protocol_id::TYPE_OF_PROTOCOL_ID
    socket::Sockets.UDPSocket
    packet_receive_channel::Channel{Tuple{NetcodeAddress, Vector{UInt8}}}
    state_machine_state::Int
    connect_token_packet::Union{Nothing, ConnectTokenPacket}
    last_connection_request_packet_sent_frame::Int
end
