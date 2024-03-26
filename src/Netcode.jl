module Netcode

import Base64
import DataFrames as DF
import GarishPrint as GP
import HTTP
import Random
import SHA
import Sockets
import Sodium
import Statistics

include("protocol_constants.jl")
include("types.jl")
include("serialization.jl")
include("servers.jl")
include("simulation.jl")
include("utils.jl")

const PROTOCOL_ID = parse(TYPE_OF_PROTOCOL_ID, bytes2hex(SHA.sha3_256(cat(NETCODE_VERSION_INFO, Vector{UInt8}("Netcode.jl"), dims = 1)))[1:16], base = 16)

const RNG = Random.MersenneTwister(0)

const SERVER_SIDE_SHARED_KEY = rand(RNG, UInt8, SIZE_OF_KEY)

const ROOM_SIZE = 3

const TIMEOUT_SECONDS = TYPE_OF_TIMEOUT_SECONDS(5)

const CONNECT_TOKEN_EXPIRE_SECONDS = 10

const AUTH_SERVER_ADDRESS = Sockets.InetAddr(Sockets.localhost, 10000)

const APP_SERVER_ADDRESSES = [Sockets.InetAddr(Sockets.localhost, 10001)]

const APP_SERVER_ADDRESS = APP_SERVER_ADDRESSES[1]

const USED_CONNECT_TOKEN_HISTORY_SIZE = ROOM_SIZE

@assert 1 <= length(APP_SERVER_ADDRESSES) <= MAX_NUM_SERVER_ADDRESSES

# TODO: salts must be randomly generated during user registration
const USER_DATA = DF.DataFrame(username = ["user$(i)" for i in 1:3], salt = ["$(i)" |> SHA.sha3_256 |> bytes2hex for i in 1:3], hashed_salted_hashed_password = ["password$(i)" |> SHA.sha3_256 |> bytes2hex |> (x -> x * ("$(i)" |> SHA.sha3_256 |> bytes2hex)) |> SHA.sha3_256 |> bytes2hex for i in 1:3])

const CLIENT_USERNAME = "user1"
const CLIENT_PASSWORD = "password1"

end # module
