const NETCODE_VERSION_INFO = Vector{UInt8}("NETCODE 1.02\0")
const SIZE_OF_NETCODE_VERSION_INFO = length(NETCODE_VERSION_INFO)

const TYPE_OF_PROTOCOL_ID = UInt64

const TYPE_OF_TIMESTAMP = UInt64

const TYPE_OF_TIMEOUT_SECONDS = UInt32

const TYPE_OF_CLIENT_ID = UInt64

const SIZE_OF_USER_DATA = 32

const SIZE_OF_NONCE = 24

const SIZE_OF_KEY = 32

const SIZE_OF_HMAC = 16

const SIZE_OF_ENCRYPTED_PRIVATE_CONNECT_TOKEN_DATA = 1024

const TYPE_OF_ADDRESS_TYPE = UInt8

const ADDRESS_TYPE_IPV4 = TYPE_OF_ADDRESS_TYPE(1)
const TYPE_OF_IPV4_HOST = UInt32

const ADDRESS_TYPE_IPV6 = TYPE_OF_ADDRESS_TYPE(2)
const TYPE_OF_IPV6_HOST = UInt128

const TYPE_OF_PORT = UInt16

const TYPE_OF_NUM_SERVER_ADDRESSES = UInt32
const MAX_NUM_SERVER_ADDRESSES = 32

const TYPE_OF_PACKET_PREFIX = UInt8

const TYPE_OF_PACKET_TYPE = UInt8

const SIZE_OF_CONNECT_TOKEN_PACKET = 2048

const PACKET_TYPE_CONNECTION_REQUEST_PACKET = TYPE_OF_PACKET_TYPE(0)
const SIZE_OF_CONNECTION_REQUEST_PACKET = 1078

const TYPE_OF_MAX_SEQUENCE_NUMBER = UInt64
