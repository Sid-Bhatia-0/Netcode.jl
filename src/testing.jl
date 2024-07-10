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

function load_replay_file(replay_file)
    io = open(replay_file, "r")
    simulation_replay_info = SimulationReplayInfoTest(FrameReplayInfoTest[])

    i = 1

    while !eof(io)
        frame_replay_info = Serialization.deserialize(io)

        @assert frame_replay_info.frame_number == i

        push!(simulation_replay_info.frame_replay_infos, frame_replay_info)

        i += 1
    end

    return simulation_replay_info
end

function get_clean_input_string(raw_input_string)
    if raw_input_string == "p" || raw_input_string == "b" || raw_input_string == "q"
        return ""
    else
        return raw_input_string
    end
end

function load_frame!(game_state, frame_info)
    game_state.frame_number = frame_info.frame_number

    return nothing
end

function test_debug_loop(; replay_file_save = nothing, replay_file_load = nothing, is_fast_replay = false, frame_number_load_reset = nothing)
    if is_fast_replay
        @assert !isnothing(replay_file_load)
    end

    if !isnothing(frame_number_load_reset)
        @assert !isnothing(replay_file_load)
    end

    if !isnothing(replay_file_save) && !isnothing(replay_file_load)
        @assert replay_file_save != replay_file_load
    end

    game_state = GameStateTest(1)

    simulation_replay_info_save = SimulationReplayInfoTest(FrameReplayInfoTest[])

    if !isnothing(replay_file_save)
        io_replay_file_save = open(replay_file_save, "w")
    else
        io_replay_file_save = nothing
    end

    if !isnothing(replay_file_load)
        simulation_replay_info_load = load_replay_file(replay_file_load)
        max_frames = length(simulation_replay_info_load.frame_replay_infos)
        if !isnothing(frame_number_load_reset)
            @assert frame_number_load_reset in 1 : max_frames
        end
        is_replay_input = true
    else
        simulation_replay_info_load = nothing
        max_frames = 10
        is_replay_input = false
    end

    while true
        frame_replay_info_save = FrameReplayInfoTest(0, "")

        if is_replay_input
            @assert !isnothing(simulation_replay_info_load)

            if !isnothing(frame_number_load_reset)
                Debugger.@bp
                frame_replay_info_load = simulation_replay_info_load.frame_replay_infos[frame_number_load_reset]
                load_frame!(game_state, frame_replay_info_load)

                empty!(simulation_replay_info_save.frame_replay_infos)
                for i in 1 : frame_number_load_reset - 1
                    push!(simulation_replay_info_save.frame_replay_infos, deepcopy(simulation_replay_info_load.frame_replay_infos[i]))
                end

                if !isnothing(io_replay_file_save)
                    close(io_replay_file_save)
                    io_replay_file_save = open(replay_file_save, "w")
                    for x in simulation_replay_info_save.frame_replay_infos
                        Serialization.serialize(io_replay_file_save, x)
                    end
                    flush(io_replay_file_save)
                end

                frame_number_load_reset = nothing # you don't want to keep loading the same frame again and again
            else
                frame_replay_info_load = simulation_replay_info_load.frame_replay_infos[game_state.frame_number]
            end
        else
            frame_replay_info_load = nothing
        end

        frame_replay_info_save.frame_number = game_state.frame_number

        @assert length(simulation_replay_info_save.frame_replay_infos) == game_state.frame_number - 1
        @assert frame_replay_info_save.frame_number == game_state.frame_number
        push!(simulation_replay_info_save.frame_replay_infos, frame_replay_info_save)

        raw_input_string = get_raw_input_string()

        if raw_input_string == "p"
            Debugger.@bp
        elseif raw_input_string == "b" # "b" for branch off because we are going to fork the history
            is_replay_input = false
            frame_replay_info_load = nothing
            Debugger.@bp
        elseif raw_input_string == "q"
            break
        end

        if is_replay_input
            @assert !isnothing(frame_replay_info_load)
            clean_input_string = frame_replay_info_load.clean_input_string
        else
            @assert isnothing(frame_replay_info_load)
            clean_input_string = get_clean_input_string(raw_input_string)
        end

        frame_replay_info_save.clean_input_string = clean_input_string

        @info "Progress" game_state.frame_number raw_input_string clean_input_string

        if !isnothing(io_replay_file_save)
            Serialization.serialize(io_replay_file_save, frame_replay_info_save)
            flush(io_replay_file_save)
        end

        if !is_fast_replay
            sleep(1)
        end

        if game_state.frame_number >= max_frames
            break
        end

        game_state.frame_number += 1
    end

    if !isnothing(io_replay_file_save)
        close(io_replay_file_save)
    end

    return nothing
end
