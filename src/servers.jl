function start_app_server(app_server_address, room_size, used_connect_token_history_size, key)
    room = fill(NULL_CLIENT_SLOT, room_size)

    used_connect_token_history = fill(NULL_CONNECT_TOKEN_SLOT, used_connect_token_history_size)

    socket = Sockets.UDPSocket()

    Sockets.bind(socket, app_server_address.host, app_server_address.port)

    app_server_netcode_address = NetcodeAddress(app_server_address)

    @info "Server started listening"

    while true
        client_address, data = Sockets.recvfrom(socket)

        if isempty(data)
            continue
        end

        if data[1] == PACKET_TYPE_CONNECTION_REQUEST_PACKET
            if length(data) != SIZE_OF_CONNECTION_REQUEST_PACKET
                @info "Invalid connection request packet received"
                continue
            end

            io = IOBuffer(data)

            connection_request_packet = try_read(io, ConnectionRequestPacket)
            if isnothing(connection_request_packet)
                @info "Invalid connection request packet received"
                continue
            end

            pprint(connection_request_packet)

            private_connect_token = try_decrypt(connection_request_packet, key)
            if isnothing(private_connect_token)
                @info "Invalid connection request packet received"
                continue
            end

            pprint(private_connect_token)

            if !(app_server_netcode_address in private_connect_token.netcode_addresses)
                @info "Invalid connection request packet received"
                continue
            end

            client_netcode_address = NetcodeAddress(client_address)

            if is_client_already_connected(room, client_netcode_address, private_connect_token.client_id)
                @info "Client already connected"
                continue
            end

            connect_token_slot = ConnectTokenSlot(time_ns(), connection_request_packet.encrypted_private_connect_token_data[end - SIZE_OF_HMAC + 1 : end], client_netcode_address)

            if !try_add!(used_connect_token_history, connect_token_slot)
                @info "connect token already used by another netcode_address"
                continue
            end

            pprint(used_connect_token_history)

            client_slot = ClientSlot(true, NetcodeAddress(client_address), private_connect_token.client_id)

            is_client_added = try_add!(room, client_slot)

            if is_client_added
                @info "Client accepted" client_address
            else
                @info "no empty client slots available"
                continue
            end

            pprint(room)

            if all(client_slot -> client_slot.is_used, room)
                @info "Room full" app_server_address room
                break
            end
        else
            @info "Received unknown packet type"
        end
    end

    return nothing
end

function start_client(auth_server_address, username, password)
    hashed_password = bytes2hex(SHA.sha3_256(password))

    response = HTTP.get("http://" * username * ":" * hashed_password * "@" * string(auth_server_address.host) * ":" * string(auth_server_address.port))

    if length(response.body) != SIZE_OF_CONNECT_TOKEN_PACKET
        error("Invalid connect token packet received")
    end

    connect_token_packet = try_read(IOBuffer(response.body), ConnectTokenPacket)
    if isnothing(connect_token_packet)
        error("Invalid connect token packet received")
    end

    connection_request_packet = ConnectionRequestPacket(connect_token_packet)
    pprint(connection_request_packet)

    socket = Sockets.UDPSocket()

    connection_request_packet_data = get_serialized_data(connection_request_packet)

    app_server_address = get_inetaddr(first(connect_token_packet.netcode_addresses))
    @info "Client obtained app_server_address" app_server_address

    Sockets.send(socket, app_server_address.host, app_server_address.port, connection_request_packet_data)

    return nothing
end

function auth_handler(request, df_user_data)
    i = findfirst(x -> x.first == "Authorization", request.headers)

    if isnothing(i)
        return HTTP.Response(400, "ERROR: Authorization not found in header")
    else
        if startswith(request.headers[i].second, "Basic ")
            base_64_encoded_credentials = split(request.headers[i].second)[2]
            base_64_decoded_credentials = String(Base64.base64decode(base_64_encoded_credentials))
            username, hashed_password = split(base_64_decoded_credentials, ':')

            i = findfirst(==(username), df_user_data[!, :username])

            if isnothing(i)
                return HTTP.Response(400, "ERROR: Invalid credentials")
            else
                if bytes2hex(SHA.sha3_256(hashed_password * df_user_data[i, :salt])) == df_user_data[i, :hashed_salted_hashed_password]
                    connect_token_info = ConnectTokenInfo(i)

                    pprint(connect_token_info)

                    connect_token_packet = ConnectTokenPacket(connect_token_info)

                    data = get_serialized_data(connect_token_packet)

                    return HTTP.Response(200, data)
                else
                    return HTTP.Response(400, "ERROR: Invalid credentials")
                end
            end
        else
            return HTTP.Response(400, "ERROR: Authorization type must be Basic authorization")
        end
    end
end

start_auth_server(auth_server_address, df_user_data) = HTTP.serve(request -> auth_handler(request, df_user_data), auth_server_address.host, auth_server_address.port)
