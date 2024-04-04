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

function simulate_update!(game_state, debug_info)
    update_time_theoretical = 2_000_000
    push!(debug_info.update_time_theoretical_buffer, update_time_theoretical)
    update_start_time = time_ns()
    sleep(update_time_theoretical / 1e9)
    update_end_time = time_ns()
    push!(debug_info.update_time_observed_buffer, update_end_time - update_start_time)

    return nothing
end

function sleep_to_achieve_target_frame_rate!(game_state, debug_info)
    expected_frame_end_time = game_state.game_start_time + game_state.target_ns_per_frame * game_state.frame_number
    current_time = time_ns()
    if current_time < expected_frame_end_time
        sleep_time_theoretical = expected_frame_end_time - current_time
    else
        sleep_time_theoretical = zero(TYPE_OF_TIMESTAMP)
    end
    push!(debug_info.sleep_time_theoretical_buffer, sleep_time_theoretical)

    sleep_start_time = time_ns()
    sleep(sleep_time_theoretical / 1e9)
    sleep_end_time = time_ns()
    push!(debug_info.sleep_time_observed_buffer, sleep_end_time - sleep_start_time)

    return nothing
end
