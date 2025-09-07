import struct
from twfs_tables import MUL_A, DIV_A, S1_T0, S1_T1, S1_T2, S1_T3

def BYTE0(n):
    return n & 0xFF

def BYTE1(n):
    return (n >> 8) & 0xFF

def BYTE2(n):
    return (n >> 16) & 0xFF

def BYTE3(n):
    return (n >> 24) & 0xFF

def to_uint32(n):
    return n & 0xFFFFFFFF

def to_int8(b):
    return b - 256 if b > 127 else b


def generate_header_key(combined_string):
    key_buffer = combined_string.encode('ascii')
    key_buffer_size = len(key_buffer)
    
    final_key = bytearray(128)

    for i in range(128):
        index = i % key_buffer_size
        value = key_buffer[index]
        final_key[i] = (i + value) & 0xFF 
        
    return final_key[:16]

def generate_content_sbox(combined_string, seed):
    key_buffer = combined_string.encode('ascii')
    sbox = bytearray(128)
    
    key_len = len(key_buffer)
    
    for i in range(128):
        index = (seed - i) % key_len
        char_val = key_buffer[index]
        sbox[i] = (i + (i % 3 + 2) * char_val) & 0xFF
        
    return sbox

def calculate_checksums(filename):
    checksum1 = 0
    checksum2 = 0
    for char in filename:
        char_val = ord(char)
        checksum1 += char_val
        checksum2 += char_val * 3

    offset1 = (checksum1 % 312) + 30 
    offset2_seed = (checksum2 % 212) + 33
    
    print(f"Checksum Offset 1 (for header block): {offset1}")
    print(f"Checksum Offset 2 (seed for re-keying): {offset2_seed}")
    
    return offset1, offset2_seed, checksum2


class Cipher:

    def __init__(self, key):
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes long.")
        self.key = key
        self.state = [0] * 256
        self._generate_key_schedule()
        self.keystream_buffer = bytearray()

    def _load_signed_bigendian(self, key_bytes, offset=0):
        p = key_bytes[offset:]
        temp = to_int8(p[0]); val = to_uint32(temp) << 8
        temp = to_int8(p[1]); val |= to_uint32(temp)
        val = val << 8
        temp = to_int8(p[2]); val |= to_uint32(temp)
        val = val << 8
        temp = to_int8(p[3]); val |= to_uint32(temp)
        return to_uint32(val)

    def _perform_round_update(self, v_target, v_shift_right_src, *xor_inputs):
        result = (
            (v_target << 8) ^
            (v_shift_right_src >> 8) ^
            DIV_A[v_shift_right_src & 0xFF] ^
            MUL_A[(v_target >> 24) & 0xFF]
        )
        for val in xor_inputs:
            result ^= val
        return to_uint32(result)

    def _initialize_state_from_key(self):
        k = [self._load_signed_bigendian(self.key, i) for i in range(0, 16, 4)]
        state = [
            k[0], k[1], k[2], k[3], to_uint32(~k[0]), to_uint32(~k[1]), to_uint32(~k[2]),
            to_uint32(~k[3]), k[0], k[1], k[2], k[3], to_uint32(~k[0]), to_uint32(~k[1]),
            to_uint32(~k[2]), to_uint32(~k[3])
        ]
        return k, state

    def _generate_key_schedule(self):
        k, state = self._initialize_state_from_key()
        key_schedule_output = [0] * 38
        key_schedule_output[0], key_schedule_output[1], key_schedule_output[2] = k[0], k[1], k[2]
        fsm_reg1, fsm_reg2, temp_output18 = 0, 0, 0
        for i in range(2):
            v8 = k[0] if i == 0 else state[0]
            v12 = to_uint32(~k[1]) if i == 0 else state[13]
            v14 = to_uint32(v8 + fsm_reg1)
            v15 = to_uint32(fsm_reg2 + state[10])
            v16 = (state[4] >> 8) ^ v14 ^ DIV_A[BYTE0(state[4])] ^ MUL_A[BYTE3(state[15])]
            temp_output18 = v15
            state[15] = to_uint32(v12 ^ fsm_reg2 ^ (state[15] << 8) ^ v16)
            v17 = S1_T0[BYTE0(fsm_reg1)]^S1_T1[BYTE1(fsm_reg1)]^S1_T2[BYTE2(fsm_reg1)]^S1_T3[BYTE3(fsm_reg1)]
            v79 = to_uint32(v17 + state[9])
            state[14] = self._perform_round_update(state[14], state[3], state[12], v17, to_uint32(v15 + state[15]))
            v18 = to_uint32(v17 + state[9] + state[14])
            v19 = S1_T2[BYTE2(temp_output18)]^S1_T1[BYTE1(temp_output18)]^S1_T0[BYTE0(v15)]
            v21 = to_uint32(S1_T3[BYTE3(temp_output18)]^v19); temp_output18=v79
            v22 = to_uint32(v21+state[8]); state[13] = self._perform_round_update(state[13],state[2],v21,v18,state[11]); v23 = to_uint32(v21+state[8]+state[13])
            v24 = S1_T2[BYTE2(temp_output18)]^S1_T1[BYTE1(temp_output18)]^S1_T0[BYTE0(v79)]; v26 = to_uint32(S1_T3[BYTE3(temp_output18)]^v24); temp_output18=v22
            state[12] = self._perform_round_update(state[12],state[1],v26,v23,state[10]); v80 = to_uint32(v26+state[7])
            v27 = S1_T3[BYTE3(temp_output18)]^S1_T2[BYTE2(temp_output18)]^S1_T1[BYTE1(temp_output18)]^S1_T0[BYTE0(v22)]; temp_output18=v80
            state[11] = self._perform_round_update(state[11],state[0],v27,to_uint32(v80+state[12]),state[9])
            v29 = S1_T2[BYTE2(temp_output18)]^S1_T0[BYTE0(v80)]^S1_T1[BYTE1(temp_output18)]; temp_sum = to_uint32(v27+state[6]); v31 = to_uint32(S1_T3[BYTE3(temp_output18)]^v29); temp_output18=temp_sum
            state[10] = self._perform_round_update(state[10],state[15],state[8],v31,to_uint32(temp_sum+state[11])); v32 = to_uint32(v31+state[5])
            v33 = S1_T2[BYTE2(temp_output18)]^S1_T1[BYTE1(temp_output18)]^S1_T0[BYTE0(temp_sum)]; v36 = to_uint32(S1_T3[BYTE3(temp_output18)]^v33); temp_output18=v32
            state[9] = self._perform_round_update(state[9],state[14],state[7],v36,to_uint32(v32+state[10]))
            v37 = S1_T3[BYTE3(temp_output18)]^S1_T2[BYTE2(temp_output18)]^S1_T1[BYTE1(temp_output18)]^S1_T0[BYTE0(v32)]; temp_sum = to_uint32(v36+state[4]); temp_output18=temp_sum
            state[8] = self._perform_round_update(state[8],state[13],v37,to_uint32(temp_sum+state[9]),state[6])
            v39 = S1_T2[BYTE2(temp_output18)]^S1_T0[BYTE0(temp_sum)]^S1_T1[BYTE1(temp_output18)]; temp_sum = to_uint32(v37+state[3]); v42 = to_uint32(S1_T3[BYTE3(temp_output18)]^v39); temp_output18=temp_sum
            state[7] = self._perform_round_update(state[7],state[12],state[5],v42,to_uint32(temp_sum+state[8]))
            v43 = S1_T2[BYTE2(temp_output18)]^S1_T1[BYTE1(temp_output18)]^S1_T0[BYTE0(temp_sum)]; temp_sum = to_uint32(v42+state[2]); v45 = to_uint32(S1_T3[BYTE3(temp_output18)]^v43); temp_output18=temp_sum
            state[6] = self._perform_round_update(state[6],state[11],v45,to_uint32(temp_sum+state[7]),state[4]); v81 = to_uint32(v45+state[1])
            v46 = S1_T3[BYTE3(temp_output18)]^S1_T2[BYTE2(temp_output18)]^S1_T1[BYTE1(temp_output18)]^S1_T0[BYTE0(temp_sum)]; temp_output18=v81
            state[5] = self._perform_round_update(state[5],state[10],v46,to_uint32(v81+state[6]),state[3]); v48 = to_uint32(v46+state[0])
            v50 = S1_T2[BYTE2(temp_output18)]^S1_T0[BYTE0(v81)]^S1_T1[BYTE1(temp_output18)]; v52 = to_uint32(S1_T3[BYTE3(temp_output18)]^v50); temp_output18=v48
            state[4] = self._perform_round_update(state[4],state[9],v52,to_uint32(v46+state[0]+state[5]),state[2])
            v53 = S1_T2[BYTE2(temp_output18)]^S1_T1[BYTE1(temp_output18)]^S1_T0[BYTE0(v48)]; temp_sum = to_uint32(v52+state[15]); v56 = to_uint32(S1_T3[BYTE3(temp_output18)]^v53); temp_output18=temp_sum
            state[3] = self._perform_round_update(state[3],state[8],v56,state[1],to_uint32(temp_sum+state[4])); v57 = to_uint32(v56+state[14])
            v58 = S1_T2[BYTE2(temp_output18)]^S1_T1[BYTE1(temp_output18)]^S1_T0[BYTE0(temp_sum)]; v60 = to_uint32(S1_T3[BYTE3(temp_output18)]^v58); temp_output18=v57
            state[2] = self._perform_round_update(state[2],state[7],v60,state[0],to_uint32(v57+state[3])); v62 = to_uint32(v60+state[13])
            v63 = S1_T2[BYTE2(temp_output18)]^S1_T1[BYTE1(temp_output18)]^S1_T0[BYTE0(v57)]; v66 = to_uint32(S1_T3[BYTE3(temp_output18)]^v63); temp_output18=v62
            state[1] = self._perform_round_update(state[1],state[6],v66,state[15],to_uint32(v62+state[2])); v68 = to_uint32(v66+state[12])
            v69 = S1_T2[BYTE2(temp_output18)]^S1_T1[BYTE1(temp_output18)]^S1_T0[BYTE0(v62)]; v72 = to_uint32(S1_T3[BYTE3(temp_output18)]^v69); temp_output18=v68
            v76 = to_uint32(v72^to_uint32(v68+state[1])); fsm_reg1 = to_uint32(v72+state[11]); state[0] = self._perform_round_update(state[0],state[5],v76,state[14])
            v73 = S1_T2[BYTE2(temp_output18)]^S1_T1[BYTE1(temp_output18)]^S1_T0[BYTE0(v68)]
            fsm_reg2 = to_uint32(S1_T3[BYTE3(temp_output18)]^v73)
            temp_output18 = fsm_reg1
        key_schedule_output[0:16] = state
        key_schedule_output[16], key_schedule_output[17], key_schedule_output[18], key_schedule_output[19] = v76, fsm_reg1, temp_output18, fsm_reg2
        key_schedule_output[36] = 16
        self.state[1:37] = key_schedule_output

    def sub_423450(self, state):
        
        v109 = to_uint32(state[19] + state[10])
        v125 = to_uint32(state[13] ^ (state[15] << 8) ^ (state[4] >> 8) ^ DIV_A[BYTE0(state[4])] ^ MUL_A[BYTE3(state[15])])
        state[15] = v125
        v2 = state[18]
        state[18] = v109
        v3 = S1_T3[BYTE3(v2)] ^ S1_T1[BYTE1(v2)] ^ S1_T2[BYTE2(v2)]
        v4 = BYTE0(v2)
        v5 = state[14]
        v6 = S1_T0[v4] ^ v3
        v7 = MUL_A[BYTE3(v5)]
        v8 = state[3]
        state[20] = to_uint32(v5 ^ v6 ^ to_uint32(v109 + v125))
        v9 = to_uint32((v8 >> 8) ^ DIV_A[BYTE0(v8)] ^ v7)
        v10 = BYTE2(state[18])
        v11 = to_uint32(v6 + state[9])
        v126 = to_uint32(state[12] ^ (v5 << 8) ^ v9)
        state[14] = v126
        v12 = S1_T3[BYTE3(state[18])] ^ S1_T0[BYTE0(v109)] ^ S1_T2[v10]
        v13 = BYTE1(state[18])
        state[18] = v11
        v14 = S1_T1[v13] ^ v12
        v15 = to_uint32(v11 + v126)
        v16 = state[13]
        state[21] = to_uint32(v16 ^ v14 ^ v15)
        v17 = state[2]
        v18 = state[11]
        v124 = to_uint32(v18 ^ (v16 << 8) ^ (state[2] >> 8) ^ DIV_A[BYTE0(v17)] ^ MUL_A[BYTE3(v16)])
        v19 = state[8]
        state[13] = v124
        v20 = to_uint32(v14 + v19)
        v109 = v20
        v17 = to_uint32(v6 + state[9])
        v22 = S1_T3[BYTE3(state[18])] ^ S1_T1[BYTE1(state[18])] ^ S1_T0[BYTE0(v17)]
        v23 = BYTE2(state[18])
        state[18] = v20
        v24 = S1_T2[v23] ^ v22
        v25 = to_uint32(v20 + v124)
        v26 = state[12]
        state[22] = to_uint32(v24 ^ v26 ^ v25)
        v27 = to_uint32((state[1] >> 8) ^ (v26 << 8) ^ DIV_A[BYTE0(state[1])] ^ MUL_A[BYTE3(v26)])
        v28 = state[10]
        v29 = to_uint32(v28 ^ v27)
        v30 = state[7]
        state[12] = v29
        v31 = to_uint32(v24 + v30)
        v123 = v29
        v32 = S1_T3[BYTE3(state[18])] ^ S1_T1[BYTE1(state[18])] ^ S1_T0[BYTE0(v109)]
        v33 = BYTE2(state[18])
        state[18] = v31
        v34 = S1_T2[v33] ^ v32
        v35 = to_uint32(v31 + v29)
        v36 = state[0]
        state[23] = to_uint32(v34 ^ v18 ^ v35)
        v37 = to_uint32(state[9] ^ (v36 >> 8) ^ (v18 << 8) ^ DIV_A[BYTE0(v36)] ^ MUL_A[BYTE3(v18)])
        v38 = state[6]
        state[11] = v37
        v122 = v37
        v39 = to_uint32(v34 + v38)
        v109 = v39
        v40 = S1_T3[BYTE3(state[18])] ^ S1_T1[BYTE1(state[18])] ^ S1_T0[BYTE0(v31)]
        v41 = BYTE2(state[18])
        state[18] = v39
        v42 = S1_T2[v41] ^ v40
        state[24] = to_uint32(v28 ^ v42 ^ to_uint32(v39 + v37))
        v43 = to_uint32(state[8] ^ (v28 << 8) ^ (v125 >> 8) ^ DIV_A[BYTE0(v125)] ^ MUL_A[BYTE3(v28)])
        v44 = state[5]
        state[10] = v43
        v115 = v43
        v45 = to_uint32(v42 + v44)
        v117 = v44
        v47 = S1_T3[BYTE3(state[18])] ^ S1_T1[BYTE1(state[18])] ^ S1_T0[BYTE0(v109)]
        v48 = BYTE2(state[18])
        state[18] = v45
        v49 = state[9]
        v50 = S1_T2[v48] ^ v47
        state[25] = to_uint32(v49 ^ v50 ^ to_uint32(v45 + v115))
        v51 = to_uint32(state[7] ^ (state[9] << 8) ^ (v126 >> 8) ^ DIV_A[BYTE0(v126)] ^ MUL_A[BYTE3(v49)])
        state[9] = v51
        v121 = v51
        v110 = to_uint32(v50 + state[4])
        v52 = S1_T3[BYTE3(state[18])] ^ S1_T1[BYTE1(state[18])] ^ S1_T0[BYTE0(v45)]
        v53 = BYTE2(state[18])
        state[18] = v110
        v54 = state[8]
        v55 = S1_T2[v53] ^ v52
        state[26] = to_uint32(v54 ^ v55 ^ to_uint32(v110 + v121))
        v120 = to_uint32(v38 ^ (state[8] << 8) ^ (v124 >> 8) ^ DIV_A[BYTE0(v124)] ^ MUL_A[BYTE3(v54)])
        state[8] = v120
        v56 = to_uint32(v55 + state[3])
        v57 = S1_T3[BYTE3(state[18])] ^ S1_T1[BYTE1(state[18])] ^ S1_T0[BYTE0(v110)]
        v58 = BYTE2(state[18])
        state[18] = v56
        v59 = state[7]
        v60 = S1_T2[v58] ^ v57
        state[27] = to_uint32(v60 ^ v59 ^ to_uint32(v56 + v120))
        v61 = v117
        v119 = to_uint32(v117 ^ (state[7] << 8) ^ (v123 >> 8) ^ DIV_A[BYTE0(v123)] ^ MUL_A[BYTE3(v59)])
        state[7] = v119
        v111 = to_uint32(v60 + state[2])
        v62 = S1_T2[BYTE2(state[18])] ^ S1_T3[BYTE3(state[18])] ^ S1_T0[BYTE0(v56)] ^ S1_T1[BYTE1(state[18])]
        v56 = v111
        state[18] = v111
        state[28] = to_uint32(v62 ^ v38 ^ to_uint32(v111 + v119))
        v63 = BYTE1(state[18])
        v118 = to_uint32(state[4] ^ (v38 << 8) ^ (v122 >> 8) ^ DIV_A[BYTE0(v122)] ^ MUL_A[BYTE3(v38)])
        state[6] = v118
        v112 = to_uint32(v62 + state[1])
        v64 = S1_T2[BYTE2(state[18])] ^ S1_T3[BYTE3(state[18])] ^ S1_T0[BYTE0(v56)] ^ S1_T1[v63]
        v65 = MUL_A[BYTE3(v61)]
        state[18] = v112
        state[29] = to_uint32(v64 ^ v61 ^ to_uint32(v118 + v112))
        v66 = to_uint32(state[3] ^ (v115 >> 8) ^ (v61 << 8) ^ DIV_A[BYTE0(v115)] ^ v65)
        state[5] = v66
        v67 = state[0]
        v116 = v66
        v68 = to_uint32(v64 + state[0])
        v69 = state[4]
        v70 = S1_T3[BYTE3(state[18])] ^ S1_T0[BYTE0(v112)] ^ S1_T1[BYTE1(state[18])]
        v71 = BYTE2(state[18])
        state[18] = v68
        v72 = S1_T2[v71] ^ v70
        state[30] = to_uint32(v72 ^ v69 ^ to_uint32(v68 + v116))
        v73 = to_uint32(state[2] ^ (v121 >> 8) ^ (state[4] << 8) ^ DIV_A[BYTE0(v121)] ^ MUL_A[BYTE3(v69)])
        state[4] = v73
        v75 = to_uint32(v72 + v125)
        v76 = S1_T3[BYTE3(state[18])] ^ S1_T0[BYTE0(v68)] ^ S1_T1[BYTE1(state[18])]
        v77 = BYTE2(state[18])
        state[18] = v75
        v78 = S1_T2[v77] ^ v76
        state[31] = to_uint32(v78 ^ state[3] ^ to_uint32(v75 + v73))
        v80 = to_uint32(state[1] ^ (v120 >> 8) ^ (state[3] << 8) ^ DIV_A[BYTE0(v120)] ^ MUL_A[BYTE3(state[3])])
        v81 = BYTE1(state[18])
        state[3] = v80
        v82 = BYTE0(v75)
        v83 = to_uint32(v78 + v126)
        v84 = S1_T3[BYTE3(state[18])] ^ S1_T0[v82] ^ S1_T1[v81]
        v85 = BYTE2(state[18])
        state[18] = v83
        v86 = S1_T2[v85] ^ v84
        v87 = state[2]
        state[32] = to_uint32(v86 ^ v87 ^ to_uint32(v83 + v80))
        v88 = to_uint32(v67 ^ (v119 >> 8) ^ (state[2] << 8) ^ DIV_A[BYTE0(v119)] ^ MUL_A[BYTE3(v87)])
        v113 = to_uint32(v86 + v124)
        v89 = BYTE1(state[18])
        state[2] = v88
        v90 = S1_T3[BYTE3(state[18])] ^ S1_T0[BYTE0(v83)] ^ S1_T1[v89]
        v91 = BYTE2(state[18])
        state[18] = v113
        v92 = S1_T2[v91] ^ v90
        v93 = state[1]
        state[33] = to_uint32(v93 ^ v92 ^ to_uint32(v113 + v88))
        v94 = to_uint32(v125 ^ (state[1] << 8) ^ (v118 >> 8) ^ DIV_A[BYTE0(v118)] ^ MUL_A[BYTE3(v93)])
        v95 = BYTE1(state[18])
        state[1] = v94
        v96 = to_uint32(v92 + v123)
        v97 = S1_T3[BYTE3(state[18])] ^ S1_T0[BYTE0(v113)] ^ S1_T1[v95]
        v98 = BYTE2(state[18])
        state[18] = v96
        v99 = S1_T2[v98] ^ v97
        v100 = to_uint32(v67 ^ v99 ^ to_uint32(v96 + v94))
        v101 = to_uint32(v122 + v99)
        state[34] = v100
        v102 = to_uint32((state[0] << 8) ^ (v116 >> 8) ^ DIV_A[BYTE0(v116)] ^ MUL_A[BYTE3(v67)])
        state[17] = v101
        v103 = to_uint32(v126 ^ v102)
        v104 = BYTE1(state[18])
        state[0] = v103
        v105 = S1_T3[BYTE3(state[18])] ^ S1_T0[BYTE0(v96)] ^ S1_T1[v104]
        v106 = BYTE2(state[18])
        state[18] = v101
        v107 = S1_T2[v106] ^ v105
        state[19] = v107
        state[35] = to_uint32(v107 ^ v125 ^ to_uint32(v101 + v103))


    def _ensure_keystream(self, length):
        while len(self.keystream_buffer) < length:
            counter = self.state[37]
            if counter == 16:
                temp_state_slice = self.state[1:37]
                self.sub_423450(temp_state_slice)
                self.state[1:37] = temp_state_slice
                self.state[37] = 0
                counter = 0
            keystream_word = self.state[counter + 21]
            self.state[37] = counter + 1
            self.keystream_buffer.extend(struct.pack('<I', keystream_word))

    def stream_decrypt(self, input_bytes, length):
        if length == 0:
            return bytearray()

        self._ensure_keystream(length)

        input_data = input_bytes[:length]
        keystream_data = self.keystream_buffer[:length]

        self.keystream_buffer = self.keystream_buffer[length:]

        input_int = int.from_bytes(input_data, 'little')
        keystream_int = int.from_bytes(keystream_data, 'little')

        mask = (1 << (length * 8)) - 1
        output_int = (input_int - keystream_int) & mask

        return bytearray(output_int.to_bytes(length, 'little'))
if __name__ == '__main__':
    filename = "dt_00028.dat"
    base_key = "VS#sg#^$sa2d34"
    offset1, offset2_seed, raw_checksum2 = calculate_checksums(filename)
    
    combined_string = filename + base_key
    header_key = generate_header_key(combined_string)
    print(f"Header key: {header_key.hex()}")

    try:
        with open(filename, 'rb') as f:
            file_content = f.read()
    except FileNotFoundError:
        print(f"Error: The file '{filename}' was not found.")
        exit()

    print("\n--- Header Check ---")
    header_cipher = Cipher(header_key)
    
    enc_dword1_bytes = file_content[offset1 : offset1 + 4]
    offset1 += 4
    enc_byte = file_content[offset1 : offset1 + 1]
    offset1 += 1
    enc_dword2_bytes = file_content[offset1 : offset1 + 4]
    offset1 += 4
    decrypted_dword1_bytes =header_cipher.stream_decrypt(enc_dword1_bytes, 4)
    decrypted_byte = header_cipher.stream_decrypt(enc_byte, 1)[0]
    decrypted_dword2_bytes = header_cipher.stream_decrypt(enc_dword2_bytes, 4)
    print(f"decrypted dword2_bytes: {decrypted_dword2_bytes.hex()}")

    decrypted_dword1 = struct.unpack_from('<I', decrypted_dword1_bytes, 0)[0]
    decrypted_dword2 = struct.unpack_from('<I', decrypted_dword2_bytes, 0)[0]
    
    print(f"Decrypted: dword1={decrypted_dword1}, version={decrypted_byte}, dword2={decrypted_dword2}")
    
    if decrypted_dword1 != to_uint32(decrypted_dword2 + decrypted_byte):
        print("\nError: Header integrity failed.")
        exit()
    print("Header OK.")
    print("\n--- Parsing file metadata ---")
    num_chunks = decrypted_dword2
    metadata_start_offset = offset1 + offset2_seed
    
    print(f"\nDAT file contains {num_chunks} files.")
    
    content_key_seed = (offset1-9) + offset2_seed

    
    content_sbox = generate_content_sbox(combined_string, content_key_seed)
    content_key = content_sbox[:16]
    print(f"Content key: {content_key.hex()}")
    content_cipher = Cipher(content_key)
    cunknum = 0
    while cunknum < num_chunks:
        enc_entry_size = file_content[metadata_start_offset : metadata_start_offset + 4]
        namelen = content_cipher.stream_decrypt(enc_entry_size, 4)
        namelen = struct.unpack_from('<I', namelen, 0)[0]*2

        metadata_start_offset += 4

        enc_filename = file_content[metadata_start_offset : metadata_start_offset + namelen]
        dec_filename = content_cipher.stream_decrypt(enc_filename, namelen)
        print(f"Filename: {dec_filename.decode('utf-8')}")
        metadata_start_offset += namelen


        #unk1 (4 bytes)
        enc_unk1 = file_content[metadata_start_offset : metadata_start_offset + 4]
        dec_unk1 = content_cipher.stream_decrypt(enc_unk1, 4)
        unk1 = struct.unpack_from('<I', dec_unk1, 0)[0]
        print(f"unk1: 0x{unk1:08x}")
        metadata_start_offset += 4

        #cryptflag (4 bytes)
        enc_cryptflag = file_content[metadata_start_offset : metadata_start_offset + 4]
        dec_cryptflag = content_cipher.stream_decrypt(enc_cryptflag, 4)
        cryptflag = struct.unpack_from('<I', dec_cryptflag, 0)[0]
        print(f"cryptflag: 0x{cryptflag:08x}")
        metadata_start_offset += 4

        #unk2 (4 bytes)
        enc_unk2 = file_content[metadata_start_offset : metadata_start_offset + 4]
        dec_unk2 = content_cipher.stream_decrypt(enc_unk2, 4)
        unk2 = struct.unpack_from('<I', dec_unk2, 0)[0]
        print(f"unk2: 0x{unk2:08x}")
        metadata_start_offset += 4

        #unk3 (4 bytes)
        enc_unk3 = file_content[metadata_start_offset : metadata_start_offset + 4]
        dec_unk3 = content_cipher.stream_decrypt(enc_unk3, 4)
        unk3 = struct.unpack_from('<I', dec_unk3, 0)[0]
        print(f"unk3: 0x{unk3:08x}")
        metadata_start_offset += 4

        #unk4 (4 bytes)
        enc_unk4 = file_content[metadata_start_offset : metadata_start_offset + 4]
        dec_unk4 = content_cipher.stream_decrypt(enc_unk4, 4)
        unk4 = struct.unpack_from('<I', dec_unk4, 0)[0]
        print(f"unk4: 0x{unk4:08x}")
        metadata_start_offset += 4

        #filekey (16 bytes)
        enc_filekey = file_content[metadata_start_offset : metadata_start_offset + 16]
        filekey = content_cipher.stream_decrypt(enc_filekey, 16)
        print(f"filekey: {filekey.hex()}")
        metadata_start_offset += 16
        cunknum += 1