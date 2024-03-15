import Base64
import DataFrames as DF
import HTTP
import Random
import SHA
import Sockets
import Sodium
import Statistics

const RNG = Random.MersenneTwister(0)

const NETCODE_VERSION_INFO = Vector{UInt8}("NETCODE 1.02\0")

const SIZE_OF_NETCODE_VERSION_INFO = length(NETCODE_VERSION_INFO)

const TYPE_OF_PROTOCOL_ID = UInt64

const SIZE_OF_PROTOCOL_ID = sizeof(TYPE_OF_PROTOCOL_ID)

const PROTOCOL_ID = parse(TYPE_OF_PROTOCOL_ID, bytes2hex(SHA.sha3_256(cat(NETCODE_VERSION_INFO, Vector{UInt8}("Netcode.jl"), dims = 1)))[1:16], base = 16)

const TYPE_OF_TIMESTAMP = UInt64

const SIZE_OF_TIMESTAMP = sizeof(TYPE_OF_TIMESTAMP)

const TYPE_OF_TIMEOUT_SECONDS = UInt32

const SIZE_OF_TIMEOUT_SECONDS = sizeof(TYPE_OF_TIMEOUT_SECONDS)

const TIMEOUT_SECONDS = TYPE_OF_TIMEOUT_SECONDS(5)

const CONNECT_TOKEN_EXPIRE_SECONDS = 10

const TYPE_OF_CLIENT_ID = UInt64

const SIZE_OF_CLIENT_ID = sizeof(TYPE_OF_CLIENT_ID)

const SIZE_OF_NONCE = 24

const SIZE_OF_CLIENT_TO_SERVER_KEY = 32

const SIZE_OF_SERVER_TO_CLIENT_KEY = 32

const SIZE_OF_SERVER_SIDE_SHARED_KEY = 32

const SERVER_SIDE_SHARED_KEY = rand(RNG, UInt8, SIZE_OF_SERVER_SIDE_SHARED_KEY)

const SIZE_OF_USER_DATA = 32

const SIZE_OF_HMAC = 16

const SIZE_OF_ENCRYPTED_PRIVATE_CONNECT_TOKEN_DATA = 1024

const SIZE_OF_CONNECT_TOKEN = 2048

const ROOM_SIZE = 3

const TYPE_OF_ADDRESS_TYPE = UInt8
const SIZE_OF_ADDRESS_TYPE = sizeof(TYPE_OF_ADDRESS_TYPE)
const ADDRESS_TYPE_IPV4 = TYPE_OF_ADDRESS_TYPE(1)
const ADDRESS_TYPE_IPV6 = TYPE_OF_ADDRESS_TYPE(2)

const TYPE_OF_IPV4_HOST = fieldtype(Sockets.IPv4, :host)
const SIZE_OF_IPV4_HOST = sizeof(TYPE_OF_IPV4_HOST)

const TYPE_OF_IPV4_PORT = fieldtype(Sockets.InetAddr{Sockets.IPv4}, :port)
const SIZE_OF_IPV4_PORT = sizeof(TYPE_OF_IPV4_PORT)

const TYPE_OF_IPV6_HOST = fieldtype(Sockets.IPv6, :host)
const SIZE_OF_IPV6_HOST = sizeof(TYPE_OF_IPV6_HOST)

const TYPE_OF_IPV6_PORT = fieldtype(Sockets.InetAddr{Sockets.IPv6}, :port)
const SIZE_OF_IPV6_PORT = sizeof(TYPE_OF_IPV6_PORT)

const GAME_SERVER_ADDRESS = Sockets.InetAddr(Sockets.localhost, 10000)

const GAME_SERVER_ADDRESSES = [GAME_SERVER_ADDRESS]

const TYPE_OF_NUM_SERVER_ADDRESSES = UInt32

const SIZE_OF_NUM_SERVER_ADDRESSES = sizeof(TYPE_OF_NUM_SERVER_ADDRESSES)

const MAX_GAME_SERVERS = 32

@assert 1 <= length(GAME_SERVER_ADDRESSES) <= MAX_GAME_SERVERS

const AUTH_SERVER_ADDRESS = Sockets.InetAddr(Sockets.localhost, 10001)

const NULL_TCP_SOCKET = Sockets.TCPSocket()

# TODO: salts must be randomly generated during user registration
const USER_DATA = DF.DataFrame(username = ["user$(i)" for i in 1:3], salt = ["$(i)" |> SHA.sha3_256 |> bytes2hex for i in 1:3], hashed_salted_hashed_password = ["password$(i)" |> SHA.sha3_256 |> bytes2hex |> (x -> x * ("$(i)" |> SHA.sha3_256 |> bytes2hex)) |> SHA.sha3_256 |> bytes2hex for i in 1:3])

const CLIENT_USERNAME = "user1"

const CLIENT_PASSWORD = "password1"

struct ClientSlot
    is_used::Bool
    socket::Sockets.TCPSocket
end

const NULL_CLIENT_SLOT = ClientSlot(false, NULL_TCP_SOCKET)

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

struct NetcodeInetAddr
    address_type::TYPE_OF_ADDRESS_TYPE
    address_ipv4::Sockets.InetAddr{Sockets.IPv4}
    address_ipv6::Sockets.InetAddr{Sockets.IPv6}
end

struct ConnectToken
    netcode_version_info::Vector{UInt8}
    protocol_id::TYPE_OF_PROTOCOL_ID
    create_timestamp::TYPE_OF_TIMESTAMP
    expire_timestamp::TYPE_OF_TIMESTAMP
    nonce::Vector{UInt8}
    timeout_seconds::TYPE_OF_TIMEOUT_SECONDS
    client_id::TYPE_OF_CLIENT_ID
    server_addresses::Vector{NetcodeInetAddr}
    client_to_server_key::Vector{UInt8}
    server_to_client_key::Vector{UInt8}
    user_data::Vector{UInt8}
end

struct PrivateConnectToken
    connect_token::ConnectToken
end

struct PaddedPrivateConnectToken
    connect_token::ConnectToken
end

struct PrivateConnectTokenAssociatedData
    connect_token::ConnectToken
end

struct EncryptedPrivateConnectToken
    connect_token::ConnectToken
end

function NetcodeInetAddr(address::Sockets.InetAddr{Sockets.IPv4})
    return NetcodeInetAddr(ADDRESS_TYPE_IPV4, address, Sockets.InetAddr(Sockets.IPv6(zero(TYPE_OF_IPV6_HOST)), zero(TYPE_OF_IPV6_PORT)))
end

function NetcodeInetAddr(address::Sockets.InetAddr{Sockets.IPv6})
    return NetcodeInetAddr(ADDRESS_TYPE_IPV6, Sockets.InetAddr(Sockets.IPv4(zero(TYPE_OF_IPV4_HOST)), zero(TYPE_OF_IPV4_PORT)), address)
end

function get_underlying_address(netcode_inetaddr::NetcodeInetAddr)
    if netcode_inetaddr.address_type == ADDRESS_TYPE_IPV4
        return netcode_inetaddr.address_ipv4
    elseif netcode_inetaddr.address_type == ADDRESS_TYPE_IPV6
        return netcode_inetaddr.address_ipv6
    else
        error("Unknown address_type $(netcode_inetaddr.address_type)")
    end
end

function ConnectToken(client_id)
    create_timestamp = time_ns()
    expire_timestamp = create_timestamp + CONNECT_TOKEN_EXPIRE_SECONDS * 10 ^ 9

    return ConnectToken(
        NETCODE_VERSION_INFO,
        PROTOCOL_ID,
        create_timestamp,
        expire_timestamp,
        rand(UInt8, SIZE_OF_NONCE),
        TIMEOUT_SECONDS,
        client_id,
        NetcodeInetAddr.(GAME_SERVER_ADDRESSES),
        rand(UInt8, SIZE_OF_CLIENT_TO_SERVER_KEY),
        rand(UInt8, SIZE_OF_SERVER_TO_CLIENT_KEY),
        rand(UInt8, SIZE_OF_USER_DATA),
    )
end

function Base.write(io::IO, netcode_inetaddr::NetcodeInetAddr)
    n = 0

    if netcode_inetaddr.address_type == ADDRESS_TYPE_IPV4
        n += write(io, ADDRESS_TYPE_IPV4)
        n += write(io, netcode_inetaddr.address_ipv4.host.host)
        n += write(io, netcode_inetaddr.address_ipv4.port)

    elseif netcode_inetaddr.address_type == ADDRESS_TYPE_IPV6
        n += write(io, ADDRESS_TYPE_IPV6)
        n += write(io, netcode_inetaddr.address_ipv6.host.host)
        n += write(io, netcode_inetaddr.address_ipv6.port)

    else
        error("Unknown address_type $(netcode_inetaddr.address_type)")
    end

    return n
end

function try_read(io::IO, ::Type{NetcodeInetAddr})
    address_type = read(io, TYPE_OF_ADDRESS_TYPE)

    if address_type == ADDRESS_TYPE_IPV4
        address_ipv4_host = Sockets.IPv4(read(io, TYPE_OF_IPV4_HOST))
        address_ipv4_port = read(io, TYPE_OF_IPV4_PORT)

        address_ipv6_host = Sockets.IPv6(zero(TYPE_OF_IPV6_HOST))
        address_ipv6_port = zero(TYPE_OF_IPV6_PORT)

    elseif address_type == ADDRESS_TYPE_IPV6
        address_ipv4_host = Sockets.IPv4(zero(TYPE_OF_IPV4_HOST))
        address_ipv4_port = zero(TYPE_OF_IPV4_PORT)

        address_ipv6_host = Sockets.IPv6(read(io, TYPE_OF_IPV6_HOST))
        address_ipv6_port = read(io, TYPE_OF_IPV6_PORT)

    else
        return nothing
    end

    address_ipv4 = Sockets.InetAddr(address_ipv4_host, address_ipv4_port)
    address_ipv6 = Sockets.InetAddr(address_ipv6_host, address_ipv6_port)

    return NetcodeInetAddr(address_type, address_ipv4, address_ipv6)
end

function Base.write(io::IO, private_connect_token::PrivateConnectToken)
    connect_token = private_connect_token.connect_token

    n = 0

    n += write(io, connect_token.client_id)

    n += write(io, connect_token.timeout_seconds)

    n += write(io, convert(TYPE_OF_NUM_SERVER_ADDRESSES, length(connect_token.server_addresses)))

    for server_address in connect_token.server_addresses
        n += write(io, server_address)
    end

    n += write(io, connect_token.client_to_server_key)

    n += write(io, connect_token.server_to_client_key)

    n += write(io, connect_token.user_data)

    return n
end

function Base.write(io::IO, padded_private_connect_token::PaddedPrivateConnectToken)
    connect_token = padded_private_connect_token.connect_token

    n = 0

    n += write(io, PrivateConnectToken(connect_token))

    @info "PrivateConnectToken written: $(n) bytes"

    for i in 1 : SIZE_OF_ENCRYPTED_PRIVATE_CONNECT_TOKEN_DATA - SIZE_OF_HMAC - n
        n += write(io, UInt8(0))
    end

    return n
end

function Base.write(io::IO, private_connect_token_associated_data::PrivateConnectTokenAssociatedData)
    connect_token = private_connect_token_associated_data.connect_token

    n = 0

    n += write(io, connect_token.netcode_version_info)

    n += write(io, connect_token.protocol_id)

    n += write(io, connect_token.expire_timestamp)

    return n
end

function Base.write(io::IO, encrypted_private_connect_token::EncryptedPrivateConnectToken)
    connect_token = encrypted_private_connect_token.connect_token

    io_message = IOBuffer(maxsize = SIZE_OF_ENCRYPTED_PRIVATE_CONNECT_TOKEN_DATA - SIZE_OF_HMAC)
    message_length = write(io_message, PaddedPrivateConnectToken(connect_token))
    @assert message_length == SIZE_OF_ENCRYPTED_PRIVATE_CONNECT_TOKEN_DATA - SIZE_OF_HMAC
    @info "PaddedPrivateConnectToken written: $(message_length) bytes"

    io_associated_data = IOBuffer(maxsize = SIZE_OF_NETCODE_VERSION_INFO + SIZE_OF_PROTOCOL_ID + SIZE_OF_TIMESTAMP)
    associated_data_length = write(io_associated_data, PrivateConnectTokenAssociatedData(connect_token))
    @assert associated_data_length == SIZE_OF_NETCODE_VERSION_INFO + SIZE_OF_PROTOCOL_ID + SIZE_OF_TIMESTAMP
    @info "PrivateConnectTokenAssociatedData written: $(associated_data_length) bytes"

    ciphertext = zeros(UInt8, SIZE_OF_ENCRYPTED_PRIVATE_CONNECT_TOKEN_DATA)
    ciphertext_length_ref = Ref{UInt}()

    encrypt_status = Sodium.LibSodium.crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext, ciphertext_length_ref, io_message.data, message_length, io_associated_data.data, associated_data_length, C_NULL, connect_token.nonce, SERVER_SIDE_SHARED_KEY)
    @assert encrypt_status == 0
    @assert ciphertext_length_ref[] == SIZE_OF_ENCRYPTED_PRIVATE_CONNECT_TOKEN_DATA

    n = write(io, ciphertext)

    return n
end

function Base.write(io::IO, connect_token::ConnectToken)
    n = 0

    n += write(io, connect_token.netcode_version_info)

    n += write(io, connect_token.protocol_id)

    n += write(io, connect_token.create_timestamp)

    n += write(io, connect_token.expire_timestamp)

    n += write(io, connect_token.nonce)

    n += write(io, EncryptedPrivateConnectToken(connect_token))

    n += write(io, connect_token.timeout_seconds)

    n += write(io, convert(TYPE_OF_NUM_SERVER_ADDRESSES, length(connect_token.server_addresses)))

    for server_address in connect_token.server_addresses
        n += write(io, server_address)
    end

    n += write(io, connect_token.client_to_server_key)

    n += write(io, connect_token.server_to_client_key)

    @info "number of bytes without padding: $(n)"

    for i in 1 : SIZE_OF_CONNECT_TOKEN - n
        n += write(io, UInt8(0))
    end

    return n
end

function get_time(reference_time)
    # get time (in units of nanoseconds) since reference_time
    # places an upper bound on how much time can the program be running until time wraps around giving meaningless values
    # the conversion to Int will actually throw an error when that happens

    t = time_ns()

    if t >= reference_time
        return Int(t - reference_time)
    else
        return Int(t + (typemax(t) - reference_time))
    end
end

function simulate_update!(game_state, debug_info)
    update_time_theoretical = 2_000_000
    push!(debug_info.update_time_theoretical_buffer, update_time_theoretical)
    update_start_time = get_time(game_state.reference_time)
    sleep(update_time_theoretical / 1e9)
    update_end_time = get_time(game_state.reference_time)
    push!(debug_info.update_time_observed_buffer, update_end_time - update_start_time)

    return nothing
end

function sleep_to_achieve_target_frame_rate!(game_state, debug_info)
    sleep_time_theoretical = max(0, game_state.target_ns_per_frame * game_state.frame_number - get_time(game_state.reference_time))
    push!(debug_info.sleep_time_theoretical_buffer, sleep_time_theoretical)

    sleep_start_time = get_time(game_state.reference_time)
    sleep(sleep_time_theoretical / 1e9)
    sleep_end_time = get_time(game_state.reference_time)
    push!(debug_info.sleep_time_observed_buffer, sleep_end_time - sleep_start_time)

    return nothing
end

function create_df_debug_info(debug_info)
    return DF.DataFrame(
        # :frame_end_time_buffer => debug_info.frame_end_time_buffer,
        :frame_time => debug_info.frame_time_buffer,
        :update_time_theoretical => debug_info.update_time_theoretical_buffer,
        :update_time_observed => debug_info.update_time_observed_buffer,
        :sleep_time_theoretical => debug_info.sleep_time_theoretical_buffer,
        :sleep_time_observed => debug_info.sleep_time_observed_buffer,
    )
end

function start_game_server(game_server_address, room_size)
    room = fill(NULL_CLIENT_SLOT, 3)

    game_server = Sockets.listen(game_server_address)
    @info "Server started listening"

    for i in 1:ROOM_SIZE
        client_slot = ClientSlot(true, Sockets.accept(game_server))
        room[i] = client_slot

        client_address = Sockets.InetAddr(Sockets.getpeername(client_slot.socket)...)

        @info "Socket accepted" client_address
    end

    @info "Room full" game_server room

    return nothing
end

function start_client(auth_server_address, username, password)
    hashed_password = bytes2hex(SHA.sha3_256(password))

    response = HTTP.get("http://" * username * ":" * hashed_password * "@" * string(auth_server_address.host) * ":" * string(auth_server_address.port))

    io_connect_token = IOBuffer(copy(response.body))

    netcode_version_info = read(io_connect_token, SIZE_OF_NETCODE_VERSION_INFO)

    protocol_id = read(io_connect_token, TYPE_OF_PROTOCOL_ID)

    create_timestamp = read(io_connect_token, TYPE_OF_TIMESTAMP)

    expire_timestamp = read(io_connect_token, TYPE_OF_TIMESTAMP)

    nonce = read(io_connect_token, SIZE_OF_NONCE)

    encrypted_private_connect_token_data = read(io_connect_token, SIZE_OF_ENCRYPTED_PRIVATE_CONNECT_TOKEN_DATA)

    timeout_seconds = read(io_connect_token, TYPE_OF_TIMEOUT_SECONDS)

    num_server_addresses = read(io_connect_token, TYPE_OF_NUM_SERVER_ADDRESSES)

    server_addresses = NetcodeInetAddr[]

    for i in 1:num_server_addresses
        server_address = try_read(io_connect_token, NetcodeInetAddr)
        if !isnothing(server_address)
            push!(server_addresses, server_address)
        else
            error("Unable to read a value of type NetcodeInetAddr")
        end
    end

    client_to_server_key = read(io_connect_token, SIZE_OF_CLIENT_TO_SERVER_KEY)

    server_to_client_key = read(io_connect_token, SIZE_OF_SERVER_TO_CLIENT_KEY)

    @info "connect_token client readable data" io_connect_token.size netcode_version_info protocol_id create_timestamp expire_timestamp nonce timeout_seconds num_server_addresses server_addresses client_to_server_key server_to_client_key

    let
        # client doesn't have access to SERVER_SIDE_SHARED_KEY so it cannot decrypt the encrypted_private_connect_token_data. But I am still accessing the global variable SERVER_SIDE_SHARED_KEY and decrypting it for testing purposes

        decrypted = zeros(UInt8, SIZE_OF_ENCRYPTED_PRIVATE_CONNECT_TOKEN_DATA - SIZE_OF_HMAC)
        decrypted_length_ref = Ref{UInt}()

        ciphertext = encrypted_private_connect_token_data

        io_associated_data = IOBuffer(maxsize = SIZE_OF_NETCODE_VERSION_INFO + SIZE_OF_PROTOCOL_ID + SIZE_OF_TIMESTAMP)

        write(io_associated_data, NETCODE_VERSION_INFO)

        write(io_associated_data, protocol_id)

        write(io_associated_data, expire_timestamp)

        decrypt_status = Sodium.LibSodium.crypto_aead_xchacha20poly1305_ietf_decrypt(decrypted, decrypted_length_ref, C_NULL, ciphertext, length(ciphertext), io_associated_data.data, io_associated_data.size, nonce, SERVER_SIDE_SHARED_KEY)
        @assert decrypt_status == 0

        io_decrypted = IOBuffer(decrypted)

        client_id = read(io_decrypted, TYPE_OF_CLIENT_ID)

        timeout_seconds = read(io_decrypted, TYPE_OF_TIMEOUT_SECONDS)

        num_server_addresses = read(io_decrypted, TYPE_OF_NUM_SERVER_ADDRESSES)

        server_addresses = NetcodeInetAddr[]

        for i in 1:num_server_addresses
            server_address = try_read(io_decrypted, NetcodeInetAddr)
            if !isnothing(server_address)
                push!(server_addresses, server_address)
            else
                error("Unable to read a value of type NetcodeInetAddr")
            end
        end

        client_to_server_key = read(io_decrypted, SIZE_OF_CLIENT_TO_SERVER_KEY)

        server_to_client_key = read(io_decrypted, SIZE_OF_SERVER_TO_CLIENT_KEY)

        user_data = read(io_decrypted, SIZE_OF_USER_DATA)

        @info "connect_token client un-readable data (for testing)" decrypt_status client_id timeout_seconds num_server_addresses server_addresses client_to_server_key server_to_client_key user_data
    end

    game_server_address = get_underlying_address(first(server_addresses))

    @info "Client obtained game_server_address" game_server_address

    socket = Sockets.connect(game_server_address)

    client_address = Sockets.InetAddr(Sockets.getsockname(socket)...)

    @info "Client connected to game_server" client_address

    return nothing
end

function auth_handler(request)
    i = findfirst(x -> x.first == "Authorization", request.headers)

    if isnothing(i)
        return HTTP.Response(400, "ERROR: Authorization not found in header")
    else
        if startswith(request.headers[i].second, "Basic ")
            base_64_encoded_credentials = split(request.headers[i].second)[2]
            base_64_decoded_credentials = String(Base64.base64decode(base_64_encoded_credentials))
            username, hashed_password = split(base_64_decoded_credentials, ':')

            i = findfirst(==(username), USER_DATA[!, :username])

            if isnothing(i)
                return HTTP.Response(400, "ERROR: Invalid credentials")
            else
                if bytes2hex(SHA.sha3_256(hashed_password * USER_DATA[i, :salt])) == USER_DATA[i, :hashed_salted_hashed_password]
                    io = IOBuffer(maxsize = SIZE_OF_CONNECT_TOKEN)

                    connect_token = ConnectToken(i)
                    @info "connect_token struct data" connect_token.netcode_version_info connect_token.protocol_id connect_token.create_timestamp connect_token.expire_timestamp connect_token.nonce connect_token.timeout_seconds connect_token.client_id connect_token.server_addresses connect_token.client_to_server_key connect_token.server_to_client_key connect_token.user_data SERVER_SIDE_SHARED_KEY SIZE_OF_HMAC SIZE_OF_ENCRYPTED_PRIVATE_CONNECT_TOKEN_DATA SIZE_OF_CONNECT_TOKEN

                    write(io, connect_token)

                    return HTTP.Response(200, io.data)
                else
                    return HTTP.Response(400, "ERROR: Invalid credentials")
                end
            end
        else
            return HTTP.Response(400, "ERROR: Authorization type must be Basic authorization")
        end
    end
end

start_auth_server(auth_server_address) = HTTP.serve(auth_handler, auth_server_address.host, auth_server_address.port)

function start()
    target_frame_rate = 60
    total_frames = target_frame_rate * 2
    target_ns_per_frame = 1_000_000_000 ÷ target_frame_rate

    debug_info = DebugInfo(Int[], Int[], Int[], Int[], Int[], Int[])
    game_state = GameState(time_ns(), 1, target_frame_rate, target_ns_per_frame)

    while game_state.frame_number <= total_frames
        # GLFW.PollEvents()

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
    display(df_debug_info)
    display(DF.describe(df_debug_info, :min, :max, :mean, :std))

    return nothing
end

if length(ARGS) == 1
    if ARGS[1] == "--game_server"
        @info "Running as game_server" GAME_SERVER_ADDRESS AUTH_SERVER_ADDRESS

        start_game_server(GAME_SERVER_ADDRESS, ROOM_SIZE)

    elseif ARGS[1] == "--auth_server"
        @info "Running as auth_server" GAME_SERVER_ADDRESS AUTH_SERVER_ADDRESS

        start_auth_server(AUTH_SERVER_ADDRESS)

    elseif ARGS[1] == "--client"
        @info "Running as client" GAME_SERVER_ADDRESS AUTH_SERVER_ADDRESS

        start_client(AUTH_SERVER_ADDRESS, CLIENT_USERNAME, CLIENT_PASSWORD)

    else
        error("Invalid command line argument $(ARGS[1])")
    end
elseif length(ARGS) > 1
    error("This script accepts at most one command line flag")
end

# start()