import sys, getopt, time
import numpy as np


# Permutation vectors, adjusted for 0 indexing
ip_vector = [1, 5, 2, 0, 3, 7, 4, 6]
ip_inverse_vector = [3, 0, 2, 4, 6, 1, 7, 5]
p10_vector = [2, 4, 1, 6, 3, 9, 0, 8, 7, 5]
p8_vector = [5, 2, 6, 3, 7, 4, 9, 8]
ep_vector = [3, 0, 1, 2, 1, 2, 3, 0]
p4_vector = [1, 3, 2, 0]
inner_vector = [1, 2]
outer_vector = [0, 3]

# S-Boxes for substituting values
S0 = np.array([[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]])
S1 = np.array([[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]])


def str_to_bitarray(plaintext: str):
    # Convert input string to bit array
    return np.array([int(char) for char in plaintext], dtype=np.uint8)


def bitwise_xor(bitarray1: np.array, bitarray2: np.array):
    # Perform bitwise XOR operation on two bit arrays
    return bitarray1 ^ bitarray2


def permute_array(bitarray: np.array, permutation: np.array):
    # Permute a bit array based on a given vector
    return bitarray[np.array(permutation)]


def split_array(bitarray: np.array):
    # Split a bit array in two equal halves
    return np.split(bitarray, 2)


def merge_arrays(bitarray1: np.array, bitarray2: np.array):
    # Merge two bit arrays into a single one
    return np.concatenate([bitarray1, bitarray2])


def circular_ls(bitarray: np.array, places: int):
    # Perform a circular left shift of given places on a bit array
    return np.roll(bitarray, -places)


def bin_to_int(bitarray: np.array):
    # Convert a bit array into its integer equivalent
    return bitarray.dot(1 << np.arange(bitarray.size)[::-1])


def int_to_bit(num: int):
    # Convert an integer into its bit array equivalent
    return np.array(list(np.binary_repr(num, width=2)), dtype=np.uint8)


def s_box_substitution(bitarray: np.array, s_box: np.array):
    # Substitute values on predetermined S-Boxes and get new bit array
    row = bin_to_int(permute_array(bitarray, outer_vector))
    column = bin_to_int(permute_array(bitarray, inner_vector))
    return int_to_bit(s_box[row, column])


def generate_keys(long_key: np.array):
    # Generation of first key
    p10 = permute_array(long_key, p10_vector)
    halves = split_array(p10)
    left_ls1 = circular_ls(halves[0], 1)
    right_ls1 = circular_ls(halves[1], 1)
    merge1 = merge_arrays(left_ls1, right_ls1)
    key1 = permute_array(merge1, p8_vector)

    # Generation of second key
    left_ls2 = circular_ls(left_ls1, 2)
    right_ls2 = circular_ls(right_ls1, 2)
    merge2 = merge_arrays(left_ls2, right_ls2)
    key2 = permute_array(merge2, p8_vector)

    return np.array([key1, key2])


def cipher(bitarray: np.array, keys: np.array, mode: str):
    # First iteration of algorithm
    ip = permute_array(bitarray, ip_vector)
    ip_halves = split_array(ip)
    ep1 = permute_array(ip_halves[1], ep_vector)
    xor1 = bitwise_xor(ep1, keys[0]) if mode == "encrypt" else bitwise_xor(ep1, keys[1])
    xor1_halves = split_array(xor1)
    s0_bits1 = s_box_substitution(xor1_halves[0], S0)
    s1_bits1 = s_box_substitution(xor1_halves[1], S1)
    sbox_bits1 = merge_arrays(s0_bits1, s1_bits1)
    first_p4 = permute_array(sbox_bits1, p4_vector)
    xor2 = bitwise_xor(first_p4, ip_halves[0])
    left_switch = ip_halves[1]
    right_switch = xor2

    # Second iteration of algorithm
    ep2 = permute_array(right_switch, ep_vector)
    xor3 = bitwise_xor(ep2, keys[1]) if mode == "encrypt" else bitwise_xor(ep2, keys[0])
    xor3_halves = split_array(xor3)
    s0_bits2 = s_box_substitution(xor3_halves[0], S0)
    s1_bits2 = s_box_substitution(xor3_halves[1], S1)
    sbox_bits2 = merge_arrays(s0_bits2, s1_bits2)
    second_p4 = permute_array(sbox_bits2, p4_vector)
    xor4 = bitwise_xor(second_p4, left_switch)
    merge = merge_arrays(xor4, right_switch)
    ciphertext = permute_array(merge, ip_inverse_vector)

    return ciphertext


if __name__ == "__main__":
    syntax = 'k:i:m:'
    key = "0000000000"
    input = "00000000"
    mode = "encrypt"

    try:
        opts, args = getopt.getopt(sys.argv[1:], syntax)
        for o, a in opts:
            if o == '-k':
                key = str_to_bitarray(str(a))
            elif o == "-i":
                input = str_to_bitarray(str(a))
            elif o == '-m':
                mode = str(a)
        
        start = time.time()
        
        keys = generate_keys(key)
        result = cipher(input, keys, mode)
        print(result)

        end = time.time()
        print(f"{end - start:.8f} seconds")

    except getopt.GetoptError as err:
        print('Error parsing args:', err)
        sys.exit(1)
    except Exception as e:
        print('Error:', e)
        sys.exit(1)
