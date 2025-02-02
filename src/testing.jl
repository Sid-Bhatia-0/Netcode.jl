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
    max_frames = target_frame_rate * 30

    connect_token_request_frame = 5 * target_frame_rate

    challenge_delay = 10 ^ 9 ÷ 10

    connection_request_packet_wait_time = 10 ^ 9 ÷ 10

    challenge_token_key = rand(rng, UInt8, SIZE_OF_KEY)

    client_username = "user1"
    client_password = "password1"

    replay_file_save_client = "client.replay"
    replay_file_load_client = nothing
    frame_number_load_reset_client = nothing

    replay_file_save_server = "server.replay"
    replay_file_load_server = nothing
    frame_number_load_reset_server = nothing

    easy_replay_switch = true

    if easy_replay_switch
        replay_file_save_client = "client_replay_run.replay"
        replay_file_load_client = "client.replay"
        frame_number_load_reset_client = nothing

        replay_file_save_server = "server_replay_run.replay"
        replay_file_load_server = "server.replay"
        frame_number_load_reset_server = nothing
    end

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
        max_frames,
        connect_token_request_frame,
        challenge_delay,
        connection_request_packet_wait_time,
        challenge_token_key,
        client_username,
        client_password,
        replay_file_save_client,
        replay_file_load_client,
        frame_number_load_reset_client,
        replay_file_save_server,
        replay_file_load_server,
        frame_number_load_reset_server,
    )
end

function test_app_server()
    test_config = TestConfig()

    if isnothing(test_config.replay_file_load_server)
        x = "app_server"
    else
        x = "app_server_replay_run"
    end

    Logging.global_logger(Netcode.create_logger(x, [Main, Netcode]))

    @info "Running as app_server"

    return start_app_server(test_config)
end

function test_auth_server()
    Logging.global_logger(Netcode.create_logger("auth_server", [Main, Netcode]))

    @info "Running as auth_server"

    test_config = TestConfig()

    return start_auth_server(test_config)
end

function test_client()
    test_config = TestConfig()

    if isnothing(test_config.replay_file_load_client)
        x = "client"
    else
        x = "client_replay_run"
    end

    Logging.global_logger(Netcode.create_logger(x, [Main, Netcode]))

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

function load_replay_file(replay_file)
    io = open(replay_file, "r")
    debug_info_load = DebugInfoTest(FrameDebugInfoTest[])

    i = 1

    while !eof(io)
        frame_debug_info_load = Serialization.deserialize(io)

        @assert frame_debug_info_load.game_state.frame_number == i

        push!(debug_info_load.frame_debug_infos, frame_debug_info_load)

        i += 1
    end

    close(io)

    return debug_info_load
end

function get_clean_input_string(raw_input_string)
    if raw_input_string == "p" || raw_input_string == "q"
        return ""
    else
        return raw_input_string
    end
end

function load_frame!(game_state, frame_debug_info_load)
    game_state.frame_number = frame_debug_info_load.game_state.frame_number
    game_state.clean_input_string = frame_debug_info_load.game_state.clean_input_string
    game_state.max_num_frames = frame_debug_info_load.game_state.max_num_frames

    return nothing
end

function load_frame_maybe!(game_state, replay_manager)
    if !isnothing(replay_manager.replay_file_load) && !isnothing(replay_manager.frame_number_load_reset)
        frame_debug_info_load = replay_manager.debug_info_load.frame_debug_infos[replay_manager.frame_number_load_reset]
        load_frame!(game_state, frame_debug_info_load)

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

function save_frame_maybe!(game_state, replay_manager)
    if !isnothing(replay_manager.replay_file_save)
        @assert game_state.frame_number == replay_manager.debug_info_save.frame_debug_infos[end].game_state.frame_number
        Serialization.serialize(replay_manager.io_replay_file_save, replay_manager.debug_info_save.frame_debug_infos[end])
        flush(replay_manager.io_replay_file_save)
    end

    return nothing
end

function test_debug_loop(; replay_file_save = nothing, replay_file_load = nothing, is_fast_replay = false, frame_number_load_reset = nothing)
    if is_fast_replay
        @assert !isnothing(replay_file_load)
    end

    game_state = GameStateTest(1, "", "", 10)

    frame_debug_info = FrameDebugInfoTest(game_state)

    replay_manager = ReplayManagerTest(;
        replay_file_save = replay_file_save,
        replay_file_load = replay_file_load,
        frame_number_load_reset = frame_number_load_reset,
    )

    while true
        push!(replay_manager.debug_info_save.frame_debug_infos, frame_debug_info)

        @assert length(replay_manager.debug_info_save.frame_debug_infos) == game_state.frame_number

        game_state.raw_input_string = get_raw_input_string()

        if game_state.raw_input_string == "p"
            Debugger.@bp
        elseif game_state.raw_input_string == "q"
            break
        end

        if !isnothing(replay_manager.replay_file_load) && replay_manager.is_replay_input
            @assert game_state.frame_number == replay_manager.debug_info_load.frame_debug_infos[game_state.frame_number].game_state.frame_number
            game_state.clean_input_string = replay_manager.debug_info_load.frame_debug_infos[game_state.frame_number].game_state.clean_input_string
        else
            game_state.clean_input_string = get_clean_input_string(game_state.raw_input_string)
        end

        @info "Progress" game_state.frame_number game_state.raw_input_string game_state.clean_input_string
        @info "Processing..."

        if !is_fast_replay
            sleep(1)
        end

        replay_manager.debug_info_save.frame_debug_infos[game_state.frame_number] = deepcopy(replay_manager.debug_info_save.frame_debug_infos[game_state.frame_number])

        save_frame_maybe!(game_state, replay_manager)
        load_frame_maybe!(game_state, replay_manager)

        if game_state.frame_number >= game_state.max_num_frames || (replay_manager.is_replay_input && game_state.frame_number == length(replay_manager.debug_info_load.frame_debug_infos))
            break
        end

        game_state.frame_number += 1
    end

    if !isnothing(replay_manager.io_replay_file_save)
        close(replay_manager.io_replay_file_save)
    end

    return nothing
end
