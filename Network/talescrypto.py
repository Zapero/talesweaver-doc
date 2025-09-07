def gen_key(key_seed):
    keyblob = bytearray(open("keyblob.bin", "rb").read())
    size = (key_seed >> 0x14 ^ key_seed >> 8 & 0xff) & 0xf ^ key_seed >> 0x14 & 0xff
    offset = (key_seed >> 0xc & 0xf00 | key_seed >> 4 & 0xf | key_seed >> 8 & 0xf0 | key_seed >> 0x10 & 0xf000)
    keyblob = keyblob[offset:offset+size]
    key_size, kout, j = len(keyblob), bytearray(range(256)), 0
    for i in range(256):
        j = (j + kout[i] + keyblob[i % key_size]) % 256
        kout[i], kout[j] = kout[j], kout[i]
    kout[0:0] = bytes.fromhex('02 00 00 00 01 00 00 00 01 01 01 00')
    kout[11:12] = kout[12:13]
    return kout


def encrypt(key: bytes, packet_buff_in: bytes, sendindex: int) -> bytes:
    packet_len = len(packet_buff_in)
    packet_buff_out = bytearray(packet_len)
    loop_index = 1
    v12 = key[11]
    
    for i in range(packet_len):
        v12 ^= packet_buff_in[i]
        v9 = (key[loop_index + 12] ^ v12)% 256
        v7 = (loop_index + 1)% 256
        v10 = (key[v7 + 12] + v9) % 256
        loop_index = (v7 + 1)% 256
        
        j = 1
        while key[0] > j:
            v11 = (key[loop_index + 12] ^ v10)% 256
            v8 = (loop_index + 1)% 256
            v10 = (key[v8 + 12] + v11) % 256
            loop_index = (v8 + 1)% 256
            j += 1
        
        packet_buff_out[i] = v10
    final_packet_buff = bytearray(packet_len+4)
    final_packet_buff[1] = (len(packet_buff_out) + 1) >> 8
    final_packet_buff[2] = (len(packet_buff_out) + 1) & 0xFF
    final_packet_buff[3] = 0
    final_packet_buff[0] = 0xAA
    final_packet_buff[3] = sendindex  #seq number
    final_packet_buff[4] = 0
    final_packet_buff[4:] = packet_buff_out[:]
    return bytes(final_packet_buff)



def decrypt(key, encpack):
    if encpack[0] == 0xAA:
        packet_length = (encpack[1] << 8) | encpack[2]
        print('p_len :'+str(packet_length))
        sequence_number = encpack[3]
        print('seq_num :'+str(sequence_number))
        packet_buff_in = encpack[4:4 + packet_length-1]
        header = encpack[:4]
    else:
        return None
    packet_len = len(packet_buff_in)
    packet_buff_out = bytearray(packet_len)
    xor_buf1 = bytearray(16 * ((key[0] + 30) >> 4))
    xor_buf2 = bytearray(16 * ((key[0] + 30) >> 4))
    temp_byte1 = 1
    temp_byte2 = key[11]

    for i in range(packet_len):
        for j in range(key[0]):
            xor_buf2[j] = key[temp_byte1 + 12]
            temp_byte1 = (temp_byte1 + 1) % 256
            xor_buf1[j] = key[temp_byte1 + 12]
            temp_byte1 = (temp_byte1 + 1) % 256

        temp_byte3 = packet_buff_in[i]


        xor_ptr2 = xor_buf2[key[4]:]
        xor_ptr1 = xor_buf1[key[4]:]
        j = key[4]

        while j > 0:
            if xor_ptr1[j-1] > temp_byte3:
                temp_byte3 += ~xor_ptr1[j-1]
                temp_byte3 += 1
            else:
                temp_byte3 -= xor_ptr1[j-1]

            temp_byte3 = (temp_byte3 ^xor_ptr2[j-1]) % 256
            j -= 1

        if xor_buf1[0] > temp_byte3:
            temp_byte3 += ~xor_buf1[0]
            temp_byte3 += 1
        else:
            temp_byte3 -= xor_buf1[0]

        temp_byte3 = (temp_byte3 ^ (xor_buf2[0] ^ temp_byte2) % 256) % 256

        packet_buff_out[i] = temp_byte3
        temp_byte2 ^= temp_byte3

    P_Cat = packet_buff_out[0]
    print('P_Cat :'+str(P_Cat))
    return  packet_buff_out