function TestConfig()
    protocol_id = parse(TYPE_OF_PROTOCOL_ID, bytes2hex(SHA.sha3_256(cat(NETCODE_VERSION_INFO, Vector{UInt8}("Netcode.jl"), dims = 1)))[1:16], base = 16)

    rng = Random.MersenneTwister(0)

    server_side_shared_key = rand(rng, UInt8, SIZE_OF_KEY)

    room_size = 3

    waiting_room_size = room_size

    timeout_seconds = TYPE_OF_TIMEOUT_SECONDS(5)

    connect_token_expire_seconds = 10

    auth_server_address = Sockets.InetAddr(Sockets.localhost, 10000)

    app_server_addresses = [Sockets.InetAddr(Sockets.localhost, 10001)]

    app_server_address = app_server_addresses[1]

    used_connect_token_history_size = room_size

    @assert 1 <= length(app_server_addresses) <= MAX_NUM_SERVER_ADDRESSES

    num_users = 8

    # TODO: salts must be randomly generated during user registration
    user_data = DF.DataFrame(username = ["user$(i)" for i in 1:num_users], salt = ["$(i)" |> SHA.sha3_256 |> bytes2hex for i in 1:num_users], hashed_salted_hashed_password = ["password$(i)" |> SHA.sha3_256 |> bytes2hex |> (x -> x * ("$(i)" |> SHA.sha3_256 |> bytes2hex)) |> SHA.sha3_256 |> bytes2hex for i in 1:num_users])

    packet_receive_channel_size = 32

    target_frame_rate = 60
    total_frames = target_frame_rate * 30

    connect_token_request_frame = 5 * target_frame_rate

    challenge_delay = 10 ^ 9 ÷ 10

    connection_request_packet_wait_time = 10 ^ 9 ÷ 10

    challenge_token_key = rand(rng, UInt8, SIZE_OF_KEY)

    client_save_debug_info_file = "client_save_debug_info.debug"
    server_save_debug_info_file = "server_save_debug_info.debug"

    client_username = "user1"
    client_password = "password1"

    return TestConfig(
        protocol_id,
        rng,
        server_side_shared_key,
        room_size,
        waiting_room_size,
        timeout_seconds,
        connect_token_expire_seconds,
        auth_server_address,
        app_server_addresses,
        app_server_address,
        used_connect_token_history_size,
        num_users,
        user_data,
        packet_receive_channel_size,
        target_frame_rate,
        total_frames,
        connect_token_request_frame,
        challenge_delay,
        connection_request_packet_wait_time,
        challenge_token_key,
        client_save_debug_info_file,
        server_save_debug_info_file,
        client_username,
        client_password,
    )
end

function test_app_server()
    test_config = TestConfig()

    return start_app_server(test_config)
end

function test_auth_server()
    test_config = TestConfig()

    return start_auth_server(test_config)
end

function test_client()
    test_config = TestConfig()

    return start_client(test_config)
end

function get_raw_input_string()
    terminal = REPL.TerminalMenus.terminal
    terminal_in = terminal.in_stream

    @assert Terminals.raw!(terminal, true)
    @assert iszero(Base.start_reading(terminal_in))
    print("") # NOTE: no bytes are read if I remove this line. Basically, if I don't print anything between the start_reading and stop_reading, then this doesn't work

    num_bytes_available = bytesavailable(terminal_in)
    raw_input_string = String(read(terminal_in, num_bytes_available))

    @assert isnothing(Base.stop_reading(terminal_in))
    @assert Terminals.raw!(terminal, false)

    return raw_input_string
end

function test_debug_loop()
    for i in 1:10
        @show i

        raw_input_string = get_raw_input_string()
        @show raw_input_string

        if raw_input_string == "p"
            Debugger.@bp
        end

        sleep(1)
    end

    return nothing
end
