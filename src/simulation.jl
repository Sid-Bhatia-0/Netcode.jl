function create_df_debug_info(debug_info)
    return DF.DataFrame([x => getfield.(debug_info.frame_debug_infos, x) for x in fieldnames(Netcode.FrameDebugInfo)]...)
end

function summarize_debug_info(debug_info)
    num_frames = length(debug_info.frame_debug_infos)

    df = create_df_debug_info(debug_info)

    num_packets_received = sum(length.(df[!, :packets_received]))
    first_packet_received_frame_number = findfirst(length.(df[!, :packets_received]) .> 0)
    last_packet_received_frame_number = findlast(length.(df[!, :packets_received]) .> 0)

    num_packets_sent = sum(length.(df[!, :packets_sent]))
    first_packet_sent_frame_number = findfirst(length.(df[!, :packets_sent]) .> 0)
    last_packet_sent_frame_number = findlast(length.(df[!, :packets_sent]) .> 0)

    df[!, :num_packets_received] = length.(df[!, :packets_received])
    df[!, :num_packets_sent] = length.(df[!, :packets_sent])

    df[!, :num_packets_sent] = length.(df[!, :packets_sent])

    time_variables = String.([:frame_time, :update_time_theoretical, :update_time_observed, :sleep_time_theoretical, :sleep_time_observed])
    variables = String.([time_variables..., :num_packets_received, :num_packets_sent])

    metrics = (:min, :q25, :median, :q75, :max, :mean, :std)

    df_summary = DF.describe(df[!, variables], metrics...)

    df_summary[!, :variable] = String.(df_summary[!, :variable])

    for column in metrics
        df_summary[!, column] = Float64.(df_summary[!, column])
    end

    for i in 1 : size(df_summary, 1)
        if df_summary[i, :variable] in time_variables
            df_summary[i, :variable] = df_summary[i, :variable] .* " (ms)"
            for column in metrics
                df_summary[i, column] = df_summary[i, column] ./ 1e6
            end
        end
    end

    @info num_frames num_packets_received first_packet_received_frame_number last_packet_received_frame_number num_packets_sent first_packet_sent_frame_number last_packet_sent_frame_number df_summary

    return nothing
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
