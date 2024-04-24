function get_probability_of_less_than_k_consecutive_failures_in_n_trials_dp_iterative(n, p_success, k)
    @assert n >= 1
    @assert k >= 1
    @assert n >= k
    @assert 0 <= p_success <= 1

    p_failure = 1 - p_success

    answer_for_k_trials = 1 - p_failure ^ k

    if n == k
        return answer_for_k_trials
    end

    arr = ones(k + 1)

    arr[k + 1] = answer_for_k_trials

    for i in k + 1 : n
        arr[mod(i, k + 1) + 1] = arr[mod(i - 1, k + 1) + 1] - p_success * (p_failure ^ k) * arr[mod(i - k - 1, k + 1) + 1]
    end

    return arr[mod(n, k + 1) + 1]
end

function get_probability_of_less_than_k_consecutive_failures_in_n_trials_dp_matrix(n, p_success, k)
    @assert n >= 1
    @assert k >= 1
    @assert n >= k
    @assert 0 <= p_success <= 1

    p_failure = 1 - p_success

    answer_for_k_trials = 1 - p_failure ^ k

    if n == k
        return answer_for_k_trials
    end

    A = zeros(k + 1, k + 1)
    A[1, 1] = 1
    A[1, end] = - p_success * (p_failure ^ k)
    for i in 1 : k
        A[i + 1, i] = 1
    end

    x = ones(k + 1)
    x[1] = answer_for_k_trials

    B = A ^ (n - k)
    y = B * x
    
    return y[1]
end

get_least_significant_bitstring(n, n_bits) = bitstring(n)[end - (n_bits - 1) : end]

function has_less_than_k_consecutive_failures(bit_sequence::Unsigned, n, k)
    @assert n >= 1
    @assert k >= 1
    @assert n >= k

    num_consecutive_failures = 0
    x = bit_sequence

    for i in 1 : n
        if iseven(x)
            num_consecutive_failures += 1

            if num_consecutive_failures == k
                return false
            end
        else
            num_consecutive_failures = 0
        end

        x = x >> 1
    end

    return true
end

function get_probability_of_generating_a_given_sequence_of_trials(bit_sequence::Unsigned, n, p_success)
    @assert n >= 1
    @assert 0 <= p_success <= 1
    @assert 8 * sizeof(bit_sequence) - leading_zeros(bit_sequence) <= n

    num_success = count_ones(bit_sequence)

    return p_success ^ num_success * (1 - p_success) ^ (n - num_success)
end

function get_smallest_unsigned_integer_type(n_bits)
    @assert n_bits >= 1

    if n_bits <= 8
        return UInt8
    elseif n_bits <= 16
        return UInt16
    elseif n_bits <= 32
        return UInt32
    elseif n_bits <= 64
        return UInt64
    elseif n_bits <= 128
        return UInt128
    else
        error("n_bits too large to fit in a primitive unsigned integer type")
    end
end

function get_probability_of_less_than_k_consecutive_failures_in_n_trials_brute_force(n, p_success, k)
    @assert n >= 1
    @assert k >= 1
    @assert n >= k
    @assert 0 <= p_success <= 1

    T = get_smallest_unsigned_integer_type(n)
    num_sequences = 2 ^ n

    answer = 0.0

    for bit_sequence in zero(T) : convert(T, num_sequences - 1)
        if has_less_than_k_consecutive_failures(bit_sequence, n, k)
            prob = get_probability_of_generating_a_given_sequence_of_trials(bit_sequence, n, p_success)
            answer += prob
        end
    end

    return answer
end

function fill_bernoulli_trials!(bit_sequence::AbstractVector{Bool}, n, p_success)
    @assert n >= 1
    @assert 0 <= p_success <= 1
    @assert length(bit_sequence) == n

    for i in 1 : n
        bit_sequence[i] = (rand() < p_success)
    end

    return nothing
end

function has_less_than_k_consecutive_failures(bit_sequence::AbstractVector{Bool}, n, k)
    @assert n >= 1
    @assert k >= 1
    @assert n >= k
    @assert length(bit_sequence) == n

    num_consecutive_failures = 0

    for i in 1 : n
        if !bit_sequence[i]
            num_consecutive_failures += 1

            if num_consecutive_failures == k
                return false
            end
        else
            num_consecutive_failures = 0
        end
    end

    return true
end

function get_probability_of_less_than_k_consecutive_failures_in_n_trials_monte_carlo(n, p_success, k, n_simulations)
    @assert n >= 1
    @assert k >= 1
    @assert n >= k
    @assert 0 <= p_success <= 1
    @assert n_simulations >= 1

    answer_numerator = 0

    bit_sequence = zeros(Bool, n) # is faster overall than falses(n) but also consumes more memory

    for i in 1 : n_simulations
        fill_bernoulli_trials!(bit_sequence, n, p_success)

        if has_less_than_k_consecutive_failures(bit_sequence, n, k)
            answer_numerator += 1
        end
    end

    return answer_numerator / n_simulations
end

n = 60 * 60 * 60
p_success = 0.8
k = 32
n_simulations = 10000

@show n
@show p_success
@show k
@show n_simulations
@show get_probability_of_less_than_k_consecutive_failures_in_n_trials_monte_carlo(n, p_success, k, n_simulations)
