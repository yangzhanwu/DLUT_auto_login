def generate_keys(key_byte):
    key = [0] * 56
    keys = [[] for _ in range(16)]
    loop = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    for i in range(7):
        for j, k in zip(range(8), reversed(range(8))):
            key[i * 8 + j] = key_byte[8 * k + i]

    for i in range(16):
        temp_left = key[0]
        temp_right = key[28]
        for _ in range(loop[i]):
            # Left shifts
            key = key[1:28] + [temp_left] + key[29:56] + [temp_right]
            temp_left = key[0]
            temp_right = key[28]

        # Permutation chosen according to the PC-2 table
        temp_key = [key[13], key[16], key[10], key[23], key[0], key[4],
                    key[2], key[27], key[14], key[5], key[20], key[9],
                    key[22], key[18], key[11], key[3], key[25], key[7],
                    key[15], key[6], key[26], key[19], key[12], key[1],
                    key[40], key[51], key[30], key[36], key[46], key[54],
                    key[29], key[39], key[50], key[44], key[32], key[47],
                    key[43], key[48], key[38], key[55], key[33], key[52],
                    key[45], key[41], key[49], key[35], key[28], key[31]]

        keys[i] = temp_key

    return keys


def get_box_binary(i):
    return format(i, '04b')


def finally_permute(end_byte):
    fp_byte = [0] * 64
    permutation_order = [
        39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25, 32, 0, 40, 8, 48, 16, 56, 24
    ]
    for index, value in enumerate(permutation_order):
        fp_byte[index] = end_byte[value]
    return fp_byte


def p_permute(s_box_byte):
    p_box_permute = [0] * 32
    permutation_order = [
        15, 6, 19, 20, 28, 11, 27, 16, 0, 14, 22, 25,
        4, 17, 30, 9, 1, 7, 23, 13, 31, 26, 2, 8,
        18, 12, 29, 5, 21, 10, 3, 24
    ]
    for i, pos in enumerate(permutation_order):
        p_box_permute[i] = s_box_byte[pos]
    return p_box_permute


def s_box_permute(expand_byte):
    s_box_byte = [0] * 32
    # Define the S-box tables
    s_boxes = [
        [  # S1
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
        ],
        [
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
        [
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
        [
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
        [
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
        [
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
        [
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
        [
            [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]

        # Add the remaining S-boxes (S2, S3, ..., S8)
    ]

    # Process each group of 6 bits through the S-boxes
    for m in range(8):
        i = expand_byte[m * 6 + 0] * 2 + expand_byte[m * 6 + 5]
        j = (expand_byte[m * 6 + 1] * 8 + expand_byte[m * 6 + 2] * 4 +
             expand_byte[m * 6 + 3] * 2 + expand_byte[m * 6 + 4])
        value = s_boxes[m][i][j]
        binary = format(value, '04b')
        for n in range(4):
            s_box_byte[m * 4 + n] = int(binary[n])

    return s_box_byte


def expand_permute(right_data):
    ep_byte = [0] * 48
    for i in range(8):
        if i == 0:
            ep_byte[i * 6 + 0] = right_data[31]
        else:
            ep_byte[i * 6 + 0] = right_data[i * 4 - 1]
        ep_byte[i * 6 + 1] = right_data[i * 4 + 0]
        ep_byte[i * 6 + 2] = right_data[i * 4 + 1]
        ep_byte[i * 6 + 3] = right_data[i * 4 + 2]
        ep_byte[i * 6 + 4] = right_data[i * 4 + 3]
        if i == 7:
            ep_byte[i * 6 + 5] = right_data[0]
        else:
            ep_byte[i * 6 + 5] = right_data[i * 4 + 4]
    return ep_byte


def xor(byte_one, byte_two):
    xor_byte = [0] * len(byte_one)
    for i in range(len(byte_one)):
        xor_byte[i] = byte_one[i] ^ byte_two[i]
    return xor_byte


def init_permute(original_data):
    ip_byte = [0] * 64
    for i, m, n in zip(range(4), range(1, 8, 2), range(0, 8, 2)):
        for j, k in zip(range(7, -1, -1), range(8)):
            ip_byte[i * 8 + k] = original_data[j * 8 + m]
            ip_byte[i * 8 + k + 32] = original_data[j * 8 + n]
    return ip_byte


def dec(data_byte, key_byte):
    keys = generate_keys(key_byte)
    ip_byte = init_permute(data_byte)
    ip_left = [0] * 32
    ip_right = [0] * 32
    temp_left = [0] * 32

    # Initial separation into left and right parts
    for k in range(32):
        ip_left[k] = ip_byte[k]
        ip_right[k] = ip_byte[32 + k]

    # The main decryption loop runs backwards from 15 to 0
    for i in range(15, -1, -1):
        for j in range(32):
            temp_left[j] = ip_left[j]
            ip_left[j] = ip_right[j]

        key = keys[i]

        # Perform the Feistel (F) function operations
        temp_right = xor(p_permute(s_box_permute(
            xor(expand_permute(ip_right), key))), temp_left)
        for n in range(32):
            ip_right[n] = temp_right[n]

    # Recombination of left and right parts
    final_data = [0] * 64
    for i in range(32):
        final_data[i] = ip_right[i]
        final_data[32 + i] = ip_left[i]

    return finally_permute(final_data)


def enc(data_byte, key_byte):
    # Assuming generate_keys() is already defined
    keys = generate_keys(key_byte)
    # Assuming init_permute() is already defined
    ip_byte = init_permute(data_byte)
    ip_left = [0] * 32
    ip_right = [0] * 32
    temp_left = [0] * 32

    # Splitting into left and right parts
    for k in range(32):
        ip_left[k] = ip_byte[k]
        ip_right[k] = ip_byte[32 + k]

    # Main encryption loop
    for i in range(16):
        for j in range(32):
            temp_left[j] = ip_left[j]
            ip_left[j] = ip_right[j]

        key = keys[i]  # Select the appropriate key for this round

        # Perform the Feistel (F) function on the right half
        temp_right = xor(p_permute(s_box_permute(
            xor(expand_permute(ip_right), key))), temp_left)
        for n in range(32):
            ip_right[n] = temp_right[n]

    # Recombine the left and right halves
    final_data = [0] * 64
    for i in range(32):
        final_data[i] = ip_right[i]
        final_data[32 + i] = ip_left[i]

    # Assuming finally_permute() is already defined
    return finally_permute(final_data)


def get_key_bytes(key):
    key_bytes = []
    leng = len(key)
    iterator = leng // 4
    remainder = leng % 4
    for i in range(iterator):
        key_bytes.append(str_to_bt(key[i*4:(i+1)*4]))
    if remainder > 0:
        key_bytes.append(str_to_bt(key[iterator*4:]))
    return key_bytes


def str_to_bt(s):
    leng = len(s)
    bt = [0] * 64
    if leng < 4:
        for i in range(leng):
            k = ord(s[i])
            for j in range(16):
                bt[16*i+j] = (k >> (15-j)) & 1
        for p in range(leng, 4):
            for q in range(16):
                bt[16*p+q] = 0
    else:
        for i in range(4):
            k = ord(s[i])
            for j in range(16):
                bt[16*i+j] = (k >> (15-j)) & 1
    return bt


def bt4_to_hex(binary):
    binary_to_hex = {
        "0000": "0", "0001": "1", "0010": "2", "0011": "3",
        "0100": "4", "0101": "5", "0110": "6", "0111": "7",
        "1000": "8", "1001": "9", "1010": "A", "1011": "B",
        "1100": "C", "1101": "D", "1110": "E", "1111": "F"
    }
    return binary_to_hex[binary]


def hex_to_bt4(hex):
    hex_to_binary = {
        "0": "0000", "1": "0001", "2": "0010", "3": "0011",
        "4": "0100", "5": "0101", "6": "0110", "7": "0111",
        "8": "1000", "9": "1001", "A": "1010", "B": "1011",
        "C": "1100", "D": "1101", "E": "1110", "F": "1111"
    }
    return hex_to_binary[hex.upper()]


def byte_to_string(byte_data):
    str = ""
    for i in range(4):
        count = 0
        for j in range(16):
            count += byte_data[16*i+j] * (2**(15-j))
        if count != 0:
            str += chr(count)
    return str


def bt64_to_hex(byte_data):
    hex = ""
    for i in range(16):
        bt = "".join(str(b) for b in byte_data[i*4:(i+1)*4])
        hex += bt4_to_hex(bt)
    return hex


def hex_to_bt64(hex):
    binary = ""
    for i in range(16):
        binary += hex_to_bt4(hex[i])
    return [int(b) for b in binary]


def str_dec(data, first_key, second_key, third_key):
    dec_str = ""
    if first_key:
        first_key_bt = get_key_bytes(first_key)
        first_length = len(first_key_bt)
    if second_key:
        second_key_bt = get_key_bytes(second_key)
        second_length = len(second_key_bt)
    if third_key:
        third_key_bt = get_key_bytes(third_key)
        third_length = len(third_key_bt)

    iterator = len(data) // 16
    for i in range(iterator):
        temp_data = data[i*16:(i+1)*16]
        str_byte = hex_to_bt64(temp_data)
        int_byte = [int(bit) for bit in str_byte]
        dec_byte = None
        if first_key and second_key and third_key:
            temp_bt = int_byte
            for x in range(third_length-1, -1, -1):
                # Assuming dec() is already defined
                temp_bt = dec(temp_bt, third_key_bt[x])
            for y in range(second_length-1, -1, -1):
                temp_bt = dec(temp_bt, second_key_bt[y])
            for z in range(first_length-1, -1, -1):
                temp_bt = dec(temp_bt, first_key_bt[z])
            dec_byte = temp_bt
        elif first_key and second_key:
            temp_bt = int_byte
            for x in range(second_length-1, -1, -1):
                temp_bt = dec(temp_bt, second_key_bt[x])
            for y in range(first_length-1, -1, -1):
                temp_bt = dec(temp_bt, first_key_bt[y])
            dec_byte = temp_bt
        elif first_key:
            temp_bt = int_byte
            for x in range(first_length-1, -1, -1):
                temp_bt = dec(temp_bt, first_key_bt[x])
            dec_byte = temp_bt

        if dec_byte is not None:
            # Assuming byte_to_string() is already defined
            dec_str += byte_to_string(dec_byte)

    return dec_str


def str_enc(data, first_key, second_key, third_key):
    enc_data = ""
    if first_key:
        first_key_bt = get_key_bytes(first_key)
        first_length = len(first_key_bt)
    if second_key:
        second_key_bt = get_key_bytes(second_key)
        second_length = len(second_key_bt)
    if third_key:
        third_key_bt = get_key_bytes(third_key)
        third_length = len(third_key_bt)

    leng = len(data)
    if leng > 0:
        if leng < 4:
            bt = str_to_bt(data)
            if first_key and second_key and third_key:
                temp_bt = bt
                for x in range(first_length):
                    temp_bt = enc(temp_bt, first_key_bt[x])
                for y in range(second_length):
                    temp_bt = enc(temp_bt, second_key_bt[y])
                for z in range(third_length):
                    temp_bt = enc(temp_bt, third_key_bt[z])
                enc_byte = temp_bt
            elif first_key and second_key:
                temp_bt = bt
                for x in range(first_length):
                    temp_bt = enc(temp_bt, first_key_bt[x])
                for y in range(second_length):
                    temp_bt = enc(temp_bt, second_key_bt[y])
                enc_byte = temp_bt
            elif first_key:
                temp_bt = bt
                for x in range(first_length):
                    temp_bt = enc(temp_bt, first_key_bt[x])
                enc_byte = temp_bt
            enc_data = bt64_to_hex(enc_byte)
        else:
            iterator = leng // 4
            remainder = leng % 4
            for i in range(iterator):
                temp_data = data[i*4:(i+1)*4]
                temp_byte = str_to_bt(temp_data)
                if first_key and second_key and third_key:
                    temp_bt = temp_byte
                    for x in range(first_length):
                        temp_bt = enc(temp_bt, first_key_bt[x])
                    for y in range(second_length):
                        temp_bt = enc(temp_bt, second_key_bt[y])
                    for z in range(third_length):
                        temp_bt = enc(temp_bt, third_key_bt[z])
                    enc_byte = temp_bt
                elif first_key and second_key:
                    temp_bt = temp_byte
                    for x in range(first_length):
                        temp_bt = enc(temp_bt, first_key_bt[x])
                    for y in range(second_length):
                        temp_bt = enc(temp_bt, second_key_bt[y])
                    enc_byte = temp_bt
                elif first_key:
                    temp_bt = temp_byte
                    for x in range(first_length):
                        temp_bt = enc(temp_bt, first_key_bt[x])
                    enc_byte = temp_bt
                enc_data += bt64_to_hex(enc_byte)
            if remainder > 0:
                remainder_data = data[iterator*4:]
                temp_byte = str_to_bt(remainder_data)
                if first_key and second_key and third_key:
                    temp_bt = temp_byte
                    for x in range(first_length):
                        temp_bt = enc(temp_bt, first_key_bt[x])
                    for y in range(second_length):
                        temp_bt = enc(temp_bt, second_key_bt[y])
                    for z in range(third_length):
                        temp_bt = enc(temp_bt, third_key_bt[z])
                    enc_byte = temp_bt
                elif first_key and second_key:
                    temp_bt = temp_byte
                    for x in range(first_length):
                        temp_bt = enc(temp_bt, first_key_bt[x])
                    for y in range(second_length):
                        temp_bt = enc(temp_bt, second_key_bt[y])
                    enc_byte = temp_bt
                elif first_key:
                    temp_bt = temp_byte
                    for x in range(first_length):
                        temp_bt = enc(temp_bt, first_key_bt[x])
                    enc_byte = temp_bt
                enc_data += bt64_to_hex(enc_byte)
    return enc_data

