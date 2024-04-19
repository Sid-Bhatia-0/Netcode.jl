function encrypt(message, associated_data, nonce, key)
    ciphertext = zeros(UInt8, length(message) + SIZE_OF_HMAC)
    ciphertext_length_ref = Ref{UInt}()

    encrypt_status = Sodium.LibSodium.crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext, ciphertext_length_ref, message, length(message), associated_data, length(associated_data), C_NULL, nonce, key)

    @assert encrypt_status == 0
    @assert ciphertext_length_ref[] == length(ciphertext)

    return ciphertext
end

function try_decrypt(ciphertext, associated_data, nonce, key)
    decrypted = zeros(UInt8, length(ciphertext) - SIZE_OF_HMAC)
    decrypted_length_ref = Ref{UInt}()

    decrypt_status = Sodium.LibSodium.crypto_aead_xchacha20poly1305_ietf_decrypt(decrypted, decrypted_length_ref, C_NULL, ciphertext, length(ciphertext), associated_data, length(associated_data), nonce, key)

    if decrypt_status != 0
        return nothing
    end

    @assert decrypted_length_ref[] == length(decrypted)

    return decrypted
end

function try_decrypt(connection_request_packet::ConnectionRequestPacket, key)
    decrypted = try_decrypt(
        connection_request_packet.encrypted_private_connect_token_data,
        get_serialized_data(PrivateConnectTokenAssociatedData(connection_request_packet)),
        connection_request_packet.nonce,
        key,
    )

    if isnothing(decrypted)
        return nothing
    end

    io = IOBuffer(decrypted)

    private_connect_token = try_read(io, PrivateConnectToken)
    if isnothing(private_connect_token)
        return nothing
    end

    return private_connect_token
end

function encrypt(challenge_token_info::ChallengeTokenInfo)
    message = get_serialized_data(ChallengeTokenMessage(challenge_token_info))

    associated_data = UInt8[]

    nonce = get_serialized_data(ExtendedUnsignedInteger(SIZE_OF_EXTENDED_SEQUENCE_NUMBER_NONCE, challenge_token_info.challenge_token_sequence_number))

    key = challenge_token_info.challenge_token_key

    ciphertext = encrypt(message, associated_data, nonce, key)

    return ciphertext
end
