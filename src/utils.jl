function pprint(x)
    GP.pprint(x)
    println()
    return nothing
end

function get_time(reference_time)
    # get time (in units of nanoseconds) since reference_time
    # places an upper bound on how much time can the program be running until time wraps around giving meaningless values
    # the conversion to Int will actually throw an error when that happens

    t = time_ns()

    if t >= reference_time
        return Int(t - reference_time)
    else
        return Int(t + (typemax(t) - reference_time))
    end
end

function is_client_already_connected(room, client_netcode_address, client_id)
    for client_slot in room
        if client_slot.is_used
            if client_slot.netcode_address == client_netcode_address
                @info "client_netcode_address already connected"
                return true
            end

            if client_slot.client_id == client_id
                @info "client_id already connected"
                return true
            end
        end
    end

    return false
end

function try_add!(used_connect_token_history::Vector{ConnectTokenSlot}, connect_token_slot::ConnectTokenSlot)
    i_oldest = 1
    last_seen_timestamp_oldest = used_connect_token_history[i_oldest].last_seen_timestamp

    for i in axes(used_connect_token_history, 1)
        if used_connect_token_history[i].hmac == connect_token_slot.hmac
            if used_connect_token_history[i].netcode_address != connect_token_slot.netcode_address
                return false
            elseif used_connect_token_history[i].last_seen_timestamp < connect_token_slot.last_seen_timestamp
                used_connect_token_history[i] = connect_token_slot
                return true
            end
        end

        if last_seen_timestamp_oldest > used_connect_token_history[i].last_seen_timestamp
            i_oldest = i
            last_seen_timestamp_oldest = used_connect_token_history[i].last_seen_timestamp
        end
    end

    used_connect_token_history[i_oldest] = connect_token_slot

    return true
end

function try_add!(room::Vector{ClientSlot}, client_slot::ClientSlot)
    for i in axes(room, 1)
        if !room[i].is_used
            room[i] = client_slot
            return true
        end
    end

    return false
end
