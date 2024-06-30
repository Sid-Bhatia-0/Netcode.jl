function create_df_debug_info()
    frame_debug_infos = DEBUG_INFO.frame_debug_infos

    return DF.DataFrame([x => getfield.(Netcode.DEBUG_INFO.frame_debug_infos, x) for x in fieldnames(Netcode.FrameDebugInfo)]...)
end

function simulate_update!(game_state)
    frame_debug_info = DEBUG_INFO.frame_debug_infos[game_state.frame_number]
    update_time_theoretical = 2_000_000
    frame_debug_info.update_time_theoretical = update_time_theoretical
    update_start_time = time_ns()
    sleep(update_time_theoretical / 1e9)
    update_end_time = time_ns()
    frame_debug_info.update_time_observed = update_end_time - update_start_time

    return nothing
end

function sleep_to_achieve_target_frame_rate!(game_state)
    frame_debug_info = DEBUG_INFO.frame_debug_infos[game_state.frame_number]

    expected_frame_end_time = game_state.game_start_time + game_state.target_ns_per_frame * game_state.frame_number
    current_time = time_ns()
    if current_time < expected_frame_end_time
        sleep_time_theoretical = expected_frame_end_time - current_time
    else
        sleep_time_theoretical = zero(current_time)
    end
    frame_debug_info.sleep_time_theoretical = sleep_time_theoretical

    sleep_start_time = time_ns()
    sleep(sleep_time_theoretical / 1e9)
    sleep_end_time = time_ns()
    frame_debug_info.sleep_time_observed = sleep_end_time - sleep_start_time

    return nothing
end
