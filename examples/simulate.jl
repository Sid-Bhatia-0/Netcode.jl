import DataFrames as DF
import Netcode
import Random
import SHA
import Sockets

const PROTOCOL_ID = parse(Netcode.TYPE_OF_PROTOCOL_ID, bytes2hex(SHA.sha3_256(cat(Netcode.NETCODE_VERSION_INFO, Vector{UInt8}("Netcode.jl"), dims = 1)))[1:16], base = 16)

const RNG = Random.MersenneTwister(0)

const SERVER_SIDE_SHARED_KEY = rand(RNG, UInt8, Netcode.SIZE_OF_KEY)

const ROOM_SIZE = 3

const WAITING_ROOM_SIZE = ROOM_SIZE * 2

const TIMEOUT_SECONDS = Netcode.TYPE_OF_TIMEOUT_SECONDS(5)

const CONNECT_TOKEN_EXPIRE_SECONDS = 10

const AUTH_SERVER_ADDRESS = Sockets.InetAddr(Sockets.localhost, 10000)

const APP_SERVER_ADDRESSES = [Sockets.InetAddr(Sockets.localhost, 10001)]

const APP_SERVER_ADDRESS = APP_SERVER_ADDRESSES[1]

const USED_CONNECT_TOKEN_HISTORY_SIZE = ROOM_SIZE

@assert 1 <= length(APP_SERVER_ADDRESSES) <= Netcode.MAX_NUM_SERVER_ADDRESSES

# TODO: salts must be randomly generated during user registration
const USER_DATA = DF.DataFrame(username = ["user$(i)" for i in 1:3], salt = ["$(i)" |> SHA.sha3_256 |> bytes2hex for i in 1:3], hashed_salted_hashed_password = ["password$(i)" |> SHA.sha3_256 |> bytes2hex |> (x -> x * ("$(i)" |> SHA.sha3_256 |> bytes2hex)) |> SHA.sha3_256 |> bytes2hex for i in 1:3])

const PACKET_RECEIVE_CHANNEL_SIZE = 32
const PACKET_SEND_CHANNEL_SIZE = 32

const TARGET_FRAME_RATE = 60
const TOTAL_FRAMES = TARGET_FRAME_RATE * 20

const CONNECT_TOKEN_REQUEST_FRAME = 5 * TARGET_FRAME_RATE

if length(ARGS) == 1
    if ARGS[1] == "--app_server"
        @info "Running as app_server" APP_SERVER_ADDRESS AUTH_SERVER_ADDRESS

        Netcode.start_app_server(PROTOCOL_ID, SERVER_SIDE_SHARED_KEY, APP_SERVER_ADDRESS, PACKET_RECEIVE_CHANNEL_SIZE, PACKET_SEND_CHANNEL_SIZE, ROOM_SIZE, WAITING_ROOM_SIZE, USED_CONNECT_TOKEN_HISTORY_SIZE, TARGET_FRAME_RATE, TOTAL_FRAMES)
    elseif ARGS[1] == "--auth_server"
        @info "Running as auth_server" APP_SERVER_ADDRESS AUTH_SERVER_ADDRESS

        Netcode.start_auth_server(AUTH_SERVER_ADDRESS, USER_DATA, PROTOCOL_ID, TIMEOUT_SECONDS, CONNECT_TOKEN_EXPIRE_SECONDS, SERVER_SIDE_SHARED_KEY, APP_SERVER_ADDRESSES)
    else
        error("Unknown command line argument $(ARGS[1])")
    end
elseif length(ARGS) == 3
    if ARGS[1] == "--client"
        @info "Running as client" APP_SERVER_ADDRESS AUTH_SERVER_ADDRESS

        client_username = ARGS[2]
        client_password = ARGS[3]

        Netcode.start_client(AUTH_SERVER_ADDRESS, client_username, client_password, PROTOCOL_ID, PACKET_RECEIVE_CHANNEL_SIZE, PACKET_SEND_CHANNEL_SIZE, TARGET_FRAME_RATE, TOTAL_FRAMES, CONNECT_TOKEN_REQUEST_FRAME)
    else
        error("Unknown command line argument $(ARGS[1])")
    end
else
    error("Invalid command line argument structure")
end
