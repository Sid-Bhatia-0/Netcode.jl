import DataFrames as DF
import Netcode
import Random
import SHA
import Sockets

const PROTOCOL_ID = parse(Netcode.TYPE_OF_PROTOCOL_ID, bytes2hex(SHA.sha3_256(cat(Netcode.NETCODE_VERSION_INFO, Vector{UInt8}("Netcode.jl"), dims = 1)))[1:16], base = 16)

const RNG = Random.MersenneTwister(0)

const SERVER_SIDE_SHARED_KEY = rand(RNG, UInt8, Netcode.SIZE_OF_KEY)

const ROOM_SIZE = 3

const TIMEOUT_SECONDS = Netcode.TYPE_OF_TIMEOUT_SECONDS(5)

const CONNECT_TOKEN_EXPIRE_SECONDS = 10

const AUTH_SERVER_ADDRESS = Sockets.InetAddr(Sockets.localhost, 10000)

const APP_SERVER_ADDRESSES = [Sockets.InetAddr(Sockets.localhost, 10001)]

const APP_SERVER_ADDRESS = APP_SERVER_ADDRESSES[1]

const USED_CONNECT_TOKEN_HISTORY_SIZE = ROOM_SIZE

@assert 1 <= length(APP_SERVER_ADDRESSES) <= Netcode.MAX_NUM_SERVER_ADDRESSES

# TODO: salts must be randomly generated during user registration
const USER_DATA = DF.DataFrame(username = ["user$(i)" for i in 1:3], salt = ["$(i)" |> SHA.sha3_256 |> bytes2hex for i in 1:3], hashed_salted_hashed_password = ["password$(i)" |> SHA.sha3_256 |> bytes2hex |> (x -> x * ("$(i)" |> SHA.sha3_256 |> bytes2hex)) |> SHA.sha3_256 |> bytes2hex for i in 1:3])

const CLIENT_USERNAME = "user1"
const CLIENT_PASSWORD = "password1"

const PACKET_RECEIVE_CHANNEL_SIZE = 32

if length(ARGS) == 1
    if ARGS[1] == "--app_server"
        @info "Running as app_server" APP_SERVER_ADDRESS AUTH_SERVER_ADDRESS

        Netcode.start_app_server(APP_SERVER_ADDRESS, ROOM_SIZE, USED_CONNECT_TOKEN_HISTORY_SIZE, SERVER_SIDE_SHARED_KEY, PROTOCOL_ID, PACKET_RECEIVE_CHANNEL_SIZE)

    elseif ARGS[1] == "--auth_server"
        @info "Running as auth_server" APP_SERVER_ADDRESS AUTH_SERVER_ADDRESS

        Netcode.start_auth_server(AUTH_SERVER_ADDRESS, USER_DATA, PROTOCOL_ID, TIMEOUT_SECONDS, CONNECT_TOKEN_EXPIRE_SECONDS, SERVER_SIDE_SHARED_KEY, APP_SERVER_ADDRESSES)

    elseif ARGS[1] == "--client"
        @info "Running as client" APP_SERVER_ADDRESS AUTH_SERVER_ADDRESS

        Netcode.start_client(AUTH_SERVER_ADDRESS, CLIENT_USERNAME, CLIENT_PASSWORD, PROTOCOL_ID, PACKET_RECEIVE_CHANNEL_SIZE)

    else
        error("Invalid command line argument $(ARGS[1])")
    end
elseif length(ARGS) > 1
    error("This script accepts at most one command line flag")
end
