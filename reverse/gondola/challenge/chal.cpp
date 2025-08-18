#include <cstdint>
#include <cstdio>
#include <cstring>

// FLAG: SEKAI{lua_wasm_1s_very_fun_3hee}
uint64_t flag_encoded[] = {0x77AB3BD16E69044A, 0x28613E1BA1B3368C, 0x5B80A90427DFD027, 0x7DD093E0AC1273C0, 0xED2C47435820775F, 0xD86CFA00C18D6218, 0x5EA21A12280769D4, 0xf40d246c3242308d };
uint64_t flag_cmp[]     = {0x291B5AC66A3AE85C, 0xDF1EF268BD407C90, 0xA9F798551B79797A, 0x91E5B6EFCE05735A, 0xF565B92F43A07C75, 0x8E3DC34D4D9107BD, 0xB43335BFC0181B24, 0xd569cc8badd8c4eb };

__attribute__((always_inline, flatten)) uint64_t flag_decode_1_deobf(uint64_t Input, uint64_t FlagKey) {
    (void)FlagKey;

    uint64_t Input_l_v1 = 0xe1ad118c39762453ul;
    uint64_t Input_l_v2 = __builtin_rotateleft64(Input_l_v1, (((0x7c25fd58f3715169ul) % 64ul) | 1ul));
    uint64_t Input_l_v3 = Input_l_v2 << (((FlagKey) % 64ul) | 1ul);
    uint64_t Input_l_v4 = Input_l_v3 & (0x6e0e9b6b76d7deeeul);
    uint64_t Input_l_v5 = Input_l_v4 - (0x170baacb8b1f180ful);

    uint64_t Input_r_v1 = 0xea7d9bc2f306ffd0ul;
    uint64_t Input_r_v2 = ~Input_r_v1;
    uint64_t Input_r_v3 = Input_r_v2 ^ (0xa5fee28fee1861b0ul);
    uint64_t Input_r_v4 = Input_r_v3 - (0x54a28265164e7be2ul);
    uint64_t Input_r_v5 = Input_r_v4 + (0xc0d962a5a1578c29ul);

    uint64_t v1 = Input ^ (__builtin_rotateleft64(Input, (((Input_l_v5 % 64ul) | 1ul))) ^ __builtin_rotateleft64(Input, (((Input_r_v5 % 64ul) | 1ul))));
    uint64_t v1_v1 = 0x841792fb1f05ba6dul;
    uint64_t v1_v2 = v1_v1 >> (((FlagKey) % 64ul) | 1ul);
    uint64_t v1_v3 = __builtin_rotateright64(v1_v2, (((FlagKey) % 64ul) | 1ul));
    uint64_t v1_v4 = v1_v3 - (FlagKey);
    uint64_t v1_v5 = v1_v4 ^ (0xd21eaf0fb3d819acul);

    uint64_t v2 = v1 + ((v1_v5));

    uint64_t v2_v1 = 0x78ed15e36bcb055ful;
    uint64_t v2_v2 = v2_v1 >> (((FlagKey) % 64ul) | 1ul);
    uint64_t v2_v3 = v2_v2 & (FlagKey);
    uint64_t v2_v4 = v2_v3 - (0x944941267bbe4ee4ul);

    uint64_t v3 = v2 + (v2 << (((v2_v4 % 64ul) | 1ul)));

    uint64_t v3_v1 = 0x702c7efafe017528ul;
    uint64_t v3_v2 = ~v3_v1;
    uint64_t v3_v3 = v3_v2 * (0xffab3f430fa3a8baul);
    uint64_t v3_v4 = __builtin_rotateleft64(v3_v3, (((FlagKey) % 64ul) | 1ul));
    uint64_t v3_v5 = v3_v4 & (0x90251c7280ff34ceul);

    uint64_t v4 = __builtin_rotateleft64(v3, (((v3_v5 % 64ul) | 1ul)));

    uint64_t v4_v1 = 0xa4f66efb4aea6eaul;
    uint64_t v4_v2 = v4_v1 * (FlagKey);
    uint64_t v4_v3 = __builtin_bswap64(v4_v2);
    uint64_t v4_v4 = v4_v3 + (FlagKey);
    uint64_t v4_v5 = v4_v4 * (0xbefc7a10ae1a9d6ful);

    uint64_t v5 = v4 ^ (v4 << (((v4_v5 % 64ul) | 1ul)));

    uint64_t v5_l_v1 = 0x80bf6014cb4c5068ul;
    uint64_t v5_l_v2 = v5_l_v1 - (0xcc48046d7ee84c6bul);
    uint64_t v5_l_v3 = __builtin_bswap64(v5_l_v2);
    uint64_t v5_l_v4 = ~v5_l_v3;
    uint64_t v5_l_v5 = __builtin_rotateright64(v5_l_v4, (((0xa668afe6daab70aeul) % 64ul) | 1ul));

    uint64_t v5_r_v1 = 0xa9e63e1c8a5e7d44ul;
    uint64_t v5_r_v2 = v5_r_v1 + (0x70b0ea63461d963bul);
    uint64_t v5_r_v3 = v5_r_v2 | (0x46df06e746ee7361ul);
    uint64_t v5_r_v4 = v5_r_v3 << (((FlagKey) % 64ul) | 1ul);
    uint64_t v5_r_v5 = v5_r_v4 * (FlagKey);

    uint64_t v6 = v5 ^ (__builtin_rotateleft64(v5, (((v5_l_v5 % 64ul) | 1ul))) ^ __builtin_rotateright64(v5, (((v5_r_v5 % 64ul) | 1ul))));

    return v6;
}

__attribute__((always_inline, flatten)) uint64_t flag_decode_2_deobf(uint64_t Input, uint64_t FlagKey) {
    (void)FlagKey;

    uint64_t Input_v1 = 0x80b72e5f50681652ul;
    uint64_t Input_v2 = __builtin_bswap64(Input_v1);
    uint64_t Input_v3 = Input_v2 >> (((0x88bf0230e4316e0ful) % 64ul) | 1ul);
    uint64_t Input_v4 = Input_v3 * (FlagKey);
    uint64_t Input_v5 = Input_v4 | (0x666b5cafe24c58f4ul);

    uint64_t v1 = Input * ((Input_v5 | 1ul));
    uint64_t v1_v1 = 0x26662e6b2dc70e04ul;
    uint64_t v1_v2 = v1_v1 >> (((FlagKey) % 64ul) | 1ul);
    uint64_t v1_v3 = v1_v2 & (FlagKey);
    uint64_t v1_v4 = v1_v3 - (FlagKey);
    uint64_t v1_v5 = __builtin_rotateright64(v1_v4, (((FlagKey) % 64ul) | 1ul));

    uint64_t v2 = v1 ^ (v1 >> (((v1_v5 % 64ul) | 1ul)));

    uint64_t v2_l_v1 = 0x268532ade72b063cul;
    uint64_t v2_l_v2 = v2_l_v1 | (0xf3c293597dc54f66ul);
    uint64_t v2_l_v3 = v2_l_v2 - (FlagKey);
    uint64_t v2_l_v4 = v2_l_v3 << (((FlagKey) % 64ul) | 1ul);
    uint64_t v2_l_v5 = v2_l_v4 >> (((0x8f9477ae9721edcful) % 64ul) | 1ul);

    uint64_t v2_r_v1 = 0x8c3df86605654b31ul;
    uint64_t v2_r_v2 = v2_r_v1 * (FlagKey);
    uint64_t v2_r_v3 = v2_r_v2 - (0xaeb323d2e96abf30ul);
    uint64_t v2_r_v4 = v2_r_v3 >> (((FlagKey) % 64ul) | 1ul);

    uint64_t v3 = v2 ^ (__builtin_rotateleft64(v2, (((v2_l_v5 % 64ul) | 1ul))) ^ __builtin_rotateleft64(v2, (((v2_r_v4 % 64ul) | 1ul))));


    uint64_t v4 = __builtin_bswap64(v3);

    uint64_t v4_v1 = 0x52cfb2344de52947ul;
    uint64_t v4_v2 = v4_v1 << (((FlagKey) % 64ul) | 1ul);
    uint64_t v4_v3 = v4_v2 + (0xfd33cd355e864ad4ul);
    uint64_t v4_v4 = v4_v3 & (0x43d1cd9b14acf5caul);

    uint64_t v5 = v4 + ((v4_v4));

    return v5;
}

__attribute__((always_inline, flatten)) uint64_t flag_decode_3_deobf(uint64_t Input, uint64_t FlagKey) {
    (void)FlagKey;

    uint64_t Input_l_v1 = 0x7fb994e4c8ff84dul;
    uint64_t Input_l_v2 = Input_l_v1 << (((FlagKey) % 64ul) | 1ul);
    uint64_t Input_l_v3 = Input_l_v2 ^ (0x18cf7e54c88339f5ul);
    uint64_t Input_l_v4 = ~Input_l_v3;

    uint64_t Input_r_v1 = 0x4a6c65adff5346c0ul;
    uint64_t Input_r_v2 = Input_r_v1 + (FlagKey);
    uint64_t Input_r_v3 = Input_r_v2 * (0xce19aa6ca3e882b4ul);
    uint64_t Input_r_v4 = Input_r_v3 ^ (FlagKey);

    uint64_t v1 = Input ^ (__builtin_rotateright64(Input, (((Input_l_v4 % 64ul) | 1ul))) ^ __builtin_rotateright64(Input, (((Input_r_v4 % 64ul) | 1ul))));
    uint64_t v1_v1 = 0xf6e093231d6b79e1ul;
    uint64_t v1_v2 = v1_v1 << (((FlagKey) % 64ul) | 1ul);
    uint64_t v1_v3 = v1_v2 + (FlagKey);
    uint64_t v1_v4 = ~v1_v3;

    uint64_t v2 = v1 * ((v1_v4 | 1ul));

    uint64_t v2_l_v1 = 0x9a9c89b6a50b3ad2ul;
    uint64_t v2_l_v2 = __builtin_bswap64(v2_l_v1);
    uint64_t v2_l_v3 = v2_l_v2 << (((0xcab8c51648ae9c93ul) % 64ul) | 1ul);
    uint64_t v2_l_v4 = v2_l_v3 >> (((0x8f4da6ec5c07f03aul) % 64ul) | 1ul);

    uint64_t v2_r_v1 = 0x48158b40b00ca918ul;
    uint64_t v2_r_v2 = v2_r_v1 | (FlagKey);
    uint64_t v2_r_v3 = v2_r_v2 & (0xdc6dbdddc9dde146ul);
    uint64_t v2_r_v4 = v2_r_v3 * (0x290bcb24e6d0bcbcul);
    uint64_t v2_r_v5 = __builtin_rotateleft64(v2_r_v4, (((0xb8437a02080179f4ul) % 64ul) | 1ul));

    uint64_t v3 = v2 ^ (__builtin_rotateright64(v2, (((v2_l_v4 % 64ul) | 1ul))) ^ __builtin_rotateleft64(v2, (((v2_r_v5 % 64ul) | 1ul))));

    uint64_t v3_l_v1 = 0xfe1211c5650aeb71ul;
    uint64_t v3_l_v2 = v3_l_v1 & (FlagKey);
    uint64_t v3_l_v3 = v3_l_v2 - (FlagKey);
    uint64_t v3_l_v4 = v3_l_v3 | (0xdf432b69d9f48ddaul);

    uint64_t v3_r_v1 = 0xb3b11baef6a6968dul;
    uint64_t v3_r_v2 = v3_r_v1 >> (((FlagKey) % 64ul) | 1ul);
    uint64_t v3_r_v3 = v3_r_v2 + (0x89324ad6b8ce62a5ul);
    uint64_t v3_r_v4 = v3_r_v3 << (((0x2ec42ccf9628928aul) % 64ul) | 1ul);
    uint64_t v3_r_v5 = __builtin_bswap64(v3_r_v4);

    uint64_t v4 = v3 ^ (__builtin_rotateleft64(v3, (((v3_l_v4 % 64ul) | 1ul))) ^ __builtin_rotateleft64(v3, (((v3_r_v5 % 64ul) | 1ul))));

    uint64_t v4_v1 = 0x570682071facfeeaul;
    uint64_t v4_v2 = v4_v1 + (FlagKey);
    uint64_t v4_v3 = v4_v2 >> (((0xee71ea35056683a5ul) % 64ul) | 1ul);
    uint64_t v4_v4 = v4_v3 | (0x758690d4d4295c4dul);
    uint64_t v4_v5 = v4_v4 - (FlagKey);

    uint64_t v5 = v4 - (v4 << (((v4_v5 % 64ul) | 1ul)));

    uint64_t v5_l_v1 = 0x6efe27edb28390eul;
    uint64_t v5_l_v2 = __builtin_rotateright64(v5_l_v1, (((FlagKey) % 64ul) | 1ul));
    uint64_t v5_l_v3 = v5_l_v2 - (FlagKey);
    uint64_t v5_l_v4 = v5_l_v3 & (FlagKey);
    uint64_t v5_l_v5 = v5_l_v4 - (FlagKey);

    uint64_t v5_r_v1 = 0x4aef4c9be79aa373ul;
    uint64_t v5_r_v2 = v5_r_v1 + (0x926072e0a05e5043ul);
    uint64_t v5_r_v3 = __builtin_rotateleft64(v5_r_v2, (((0x16e3c8d170817b9eul) % 64ul) | 1ul));
    uint64_t v5_r_v4 = v5_r_v3 << (((0x33aa190abbbbd944ul) % 64ul) | 1ul);

    uint64_t v6 = v5 ^ (__builtin_rotateright64(v5, (((v5_l_v5 % 64ul) | 1ul))) ^ __builtin_rotateright64(v5, (((v5_r_v4 % 64ul) | 1ul))));

    return v6;
}

__attribute__((always_inline, flatten)) uint64_t flag_decode_4_deobf(uint64_t Input, uint64_t FlagKey) {
    (void)FlagKey;

    uint64_t Input_v1 = 0x4b9696f32a55ecccul;
    uint64_t Input_v2 = __builtin_bswap64(Input_v1);
    uint64_t Input_v3 = __builtin_rotateleft64(Input_v2, (((FlagKey) % 64ul) | 1ul));
    uint64_t Input_v4 = __builtin_rotateright64(Input_v3, (((FlagKey) % 64ul) | 1ul));

    uint64_t v1 = __builtin_rotateleft64(Input, (((Input_v4 % 64ul) | 1ul)));
    uint64_t v1_v1 = 0x2d3d73c4ae4e4f8eul;
    uint64_t v1_v2 = v1_v1 - (FlagKey);
    uint64_t v1_v3 = v1_v2 & (FlagKey);
    uint64_t v1_v4 = ~v1_v3;
    uint64_t v1_v5 = __builtin_rotateright64(v1_v4, (((0x5a19151f0baf774ful) % 64ul) | 1ul));

    uint64_t v2 = v1 + ((v1_v5));

    uint64_t v2_v1 = 0x47ce8f31f1792cbul;
    uint64_t v2_v2 = v2_v1 | (FlagKey);
    uint64_t v2_v3 = v2_v2 >> (((FlagKey) % 64ul) | 1ul);
    uint64_t v2_v4 = __builtin_rotateleft64(v2_v3, (((FlagKey) % 64ul) | 1ul));

    uint64_t v3 = v2 ^ ((v2_v4));

    uint64_t v3_v1 = 0x85e5093f00cfa998ul;
    uint64_t v3_v2 = v3_v1 >> (((FlagKey) % 64ul) | 1ul);
    uint64_t v3_v3 = __builtin_bswap64(v3_v2);
    uint64_t v3_v4 = __builtin_rotateleft64(v3_v3, (((0x2e4d34d640c4c713ul) % 64ul) | 1ul));

    uint64_t v4 = v3 ^ (v3 >> (((v3_v4 % 64ul) | 1ul)));

    uint64_t v4_l_v1 = 0xe02b7343a73a955bul;
    uint64_t v4_l_v2 = v4_l_v1 - (0x52c2395795a3b70ful);
    uint64_t v4_l_v3 = __builtin_rotateright64(v4_l_v2, (((0x34cfd09ccb869f58ul) % 64ul) | 1ul));
    uint64_t v4_l_v4 = v4_l_v3 << (((FlagKey) % 64ul) | 1ul);
    uint64_t v4_l_v5 = __builtin_bswap64(v4_l_v4);

    uint64_t v4_r_v1 = 0x42f83a3a137f05caul;
    uint64_t v4_r_v2 = v4_r_v1 - (FlagKey);
    uint64_t v4_r_v3 = ~v4_r_v2;
    uint64_t v4_r_v4 = __builtin_rotateleft64(v4_r_v3, (((0x9d548ded232f417aul) % 64ul) | 1ul));

    uint64_t v5 = v4 ^ (__builtin_rotateright64(v4, (((v4_l_v5 % 64ul) | 1ul))) ^ __builtin_rotateleft64(v4, (((v4_r_v4 % 64ul) | 1ul))));

    uint64_t v5_v1 = 0x53c694bac0989744ul;
    uint64_t v5_v2 = __builtin_bswap64(v5_v1);
    uint64_t v5_v3 = v5_v2 >> (((0xfc422a97153dcbeful) % 64ul) | 1ul);
    uint64_t v5_v4 = ~v5_v3;
    uint64_t v5_v5 = v5_v4 | (FlagKey);

    uint64_t v6 = v5 ^ (v5 << (((v5_v5 % 64ul) | 1ul)));

    uint64_t v6_v1 = 0xdc378a07fbc9f1f2ul;
    uint64_t v6_v2 = v6_v1 << (((FlagKey) % 64ul) | 1ul);
    uint64_t v6_v3 = ~v6_v2;
    uint64_t v6_v4 = v6_v3 * (FlagKey);

    uint64_t v7 = v6 + (v6 << (((v6_v4 % 64ul) | 1ul)));

    uint64_t v7_v1 = 0x8f91c83a01236831ul;
    uint64_t v7_v2 = v7_v1 >> (((FlagKey) % 64ul) | 1ul);
    uint64_t v7_v3 = v7_v2 - (FlagKey);
    uint64_t v7_v4 = v7_v3 << (((FlagKey) % 64ul) | 1ul);

    uint64_t v8 = v7 - (v7 << (((v7_v4 % 64ul) | 1ul)));

    return v8;
}

__attribute__((always_inline, flatten)) uint64_t flag_decode_5_deobf(uint64_t Input, uint64_t FlagKey) {
    (void)FlagKey;


    uint64_t v1 = __builtin_bswap64(Input);
    uint64_t v1_v1 = 0xf3e81c3c3198b40dul;
    uint64_t v1_v2 = v1_v1 + (FlagKey);
    uint64_t v1_v3 = __builtin_bswap64(v1_v2);
    uint64_t v1_v4 = v1_v3 | (0x70012f6d566aded7ul);
    uint64_t v1_v5 = v1_v4 * (FlagKey);

    uint64_t v2 = __builtin_rotateleft64(v1, (((v1_v5 % 64ul) | 1ul)));

    uint64_t v2_v1 = 0x54355250db0622f7ul;
    uint64_t v2_v2 = v2_v1 & (0x785c03550dcda174ul);
    uint64_t v2_v3 = __builtin_rotateleft64(v2_v2, (((0x742d711475db9b1bul) % 64ul) | 1ul));
    uint64_t v2_v4 = v2_v3 - (0xc062f64534e7b538ul);

    uint64_t v3 = v2 ^ ((v2_v4));

    uint64_t v3_v1 = 0x49d978c9ddff7110ul;
    uint64_t v3_v2 = __builtin_rotateleft64(v3_v1, (((0x62714167de81f524ul) % 64ul) | 1ul));
    uint64_t v3_v3 = v3_v2 + (FlagKey);
    uint64_t v3_v4 = __builtin_bswap64(v3_v3);
    uint64_t v3_v5 = v3_v4 ^ (0xad741af4d42d1489ul);

    uint64_t v4 = v3 + ((v3_v5));

    uint64_t v4_v1 = 0x5a86daf5c4da1693ul;
    uint64_t v4_v2 = __builtin_bswap64(v4_v1);
    uint64_t v4_v3 = v4_v2 + (0xcd3552959bb769d2ul);
    uint64_t v4_v4 = v4_v3 | (0x58a32347f574da6aul);
    uint64_t v4_v5 = v4_v4 + (0xb9764315de541f8ul);

    uint64_t v5 = v4 ^ (v4 << (((v4_v5 % 64ul) | 1ul)));

    return v5;
}

__attribute__((always_inline, flatten)) uint64_t flag_decode_6_deobf(uint64_t Input, uint64_t FlagKey) {
    (void)FlagKey;

    uint64_t Input_v1 = 0x66a2b7e381f668a4ul;
    uint64_t Input_v2 = Input_v1 << (((0xf4d325bbe5b160cul) % 64ul) | 1ul);
    uint64_t Input_v3 = __builtin_bswap64(Input_v2);
    uint64_t Input_v4 = Input_v3 ^ (FlagKey);

    uint64_t v1 = Input + ((Input_v4));
    uint64_t v1_v1 = 0xa2b8f9fe7e816708ul;
    uint64_t v1_v2 = v1_v1 & (FlagKey);
    uint64_t v1_v3 = v1_v2 * (FlagKey);
    uint64_t v1_v4 = v1_v3 - (0x40eae64b56522966ul);

    uint64_t v2 = v1 + (v1 << (((v1_v4 % 64ul) | 1ul)));

    uint64_t v2_v1 = 0x998395d8df9e82dful;
    uint64_t v2_v2 = __builtin_rotateright64(v2_v1, (((FlagKey) % 64ul) | 1ul));
    uint64_t v2_v3 = __builtin_rotateleft64(v2_v2, (((FlagKey) % 64ul) | 1ul));
    uint64_t v2_v4 = v2_v3 | (0xe017ada862aad370ul);

    uint64_t v3 = v2 - ((v2_v4));

    uint64_t v3_v1 = 0x783b3d576667a509ul;
    uint64_t v3_v2 = v3_v1 >> (((FlagKey) % 64ul) | 1ul);
    uint64_t v3_v3 = ~v3_v2;
    uint64_t v3_v4 = v3_v3 << (((FlagKey) % 64ul) | 1ul);
    uint64_t v3_v5 = v3_v4 + (FlagKey);

    uint64_t v4 = v3 ^ (v3 << (((v3_v5 % 64ul) | 1ul)));

    uint64_t v4_v1 = 0x4c93fb11e355110bul;
    uint64_t v4_v2 = v4_v1 >> (((0x6821d6788f299603ul) % 64ul) | 1ul);
    uint64_t v4_v3 = v4_v2 + (0x2169c7202a8d5b5ful);
    uint64_t v4_v4 = v4_v3 * (0xb23dec296aac7d2bul);

    uint64_t v5 = v4 ^ ((v4_v4));

    return v5;
}

__attribute__((always_inline, flatten)) uint64_t flag_decode_7_deobf(uint64_t Input, uint64_t FlagKey) {
    (void)FlagKey;

    uint64_t Input_v1 = 0x4dc4e0be24e25e9ul;
    uint64_t Input_v2 = __builtin_rotateleft64(Input_v1, (((0x96baea4db0836e1cul) % 64ul) | 1ul));
    uint64_t Input_v3 = Input_v2 | (0x13a29f7a0ff1a804ul);
    uint64_t Input_v4 = Input_v3 ^ (0x6576130930952d0cul);

    uint64_t v1 = Input - (Input << (((Input_v4 % 64ul) | 1ul)));
    uint64_t v1_v1 = 0xb9d30fecfe674370ul;
    uint64_t v1_v2 = v1_v1 | (FlagKey);
    uint64_t v1_v3 = v1_v2 >> (((FlagKey) % 64ul) | 1ul);
    uint64_t v1_v4 = __builtin_rotateright64(v1_v3, (((FlagKey) % 64ul) | 1ul));
    uint64_t v1_v5 = v1_v4 & (0x99d7bcad83394656ul);

    uint64_t v2 = v1 + ((v1_v5));

    uint64_t v2_l_v1 = 0x3a655cc8274c6729ul;
    uint64_t v2_l_v2 = v2_l_v1 - (FlagKey);
    uint64_t v2_l_v3 = ~v2_l_v2;
    uint64_t v2_l_v4 = v2_l_v3 ^ (0x1d300617598e855eul);
    uint64_t v2_l_v5 = v2_l_v4 - (FlagKey);

    uint64_t v2_r_v1 = 0x76d369579e385d68ul;
    uint64_t v2_r_v2 = v2_r_v1 + (FlagKey);
    uint64_t v2_r_v3 = v2_r_v2 & (FlagKey);
    uint64_t v2_r_v4 = v2_r_v3 ^ (0x1a2d75ce21f1184cul);

    uint64_t v3 = v2 ^ (__builtin_rotateleft64(v2, (((v2_l_v5 % 64ul) | 1ul))) ^ __builtin_rotateright64(v2, (((v2_r_v4 % 64ul) | 1ul))));


    uint64_t v4 = ~v3;

    uint64_t v4_v1 = 0xf26a3b82537f7f0dul;
    uint64_t v4_v2 = v4_v1 & (0x4cc756d2c34a59a7ul);
    uint64_t v4_v3 = v4_v2 >> (((FlagKey) % 64ul) | 1ul);
    uint64_t v4_v4 = v4_v3 | (FlagKey);

    uint64_t v5 = v4 - (v4 << (((v4_v4 % 64ul) | 1ul)));

    uint64_t v5_v1 = 0x5bbc769d45cfcbabul;
    uint64_t v5_v2 = ~v5_v1;
    uint64_t v5_v3 = v5_v2 - (FlagKey);
    uint64_t v5_v4 = v5_v3 * (0x2b58df03ec13df9ful);

    uint64_t v6 = v5 + ((v5_v4));

    uint64_t v6_v1 = 0x2db57e93381fc871ul;
    uint64_t v6_v2 = __builtin_bswap64(v6_v1);
    uint64_t v6_v3 = v6_v2 ^ (0x447b60868c4b1e67ul);
    uint64_t v6_v4 = __builtin_rotateright64(v6_v3, (((0x33aab4ce408f068ful) % 64ul) | 1ul));

    uint64_t v7 = v6 + (v6 << (((v6_v4 % 64ul) | 1ul)));

    return v7;
}

__attribute__((noopt)) int main() {
    printf("Enter flag: ");
    fflush(stdout);

    char flag[100];
    scanf("%s", flag);

    if (strlen(flag) != 32) {
        printf("Incorrect flag!\n");
        return 1;
    }
    
    auto is_valid = true;
    for (int i = 0; i < (sizeof(flag_encoded) / sizeof(uint64_t)); i++) {
        uint32_t flag_chunk;
        memcpy(&flag_chunk, &flag[i * 4], sizeof(uint32_t));

        uint64_t decoded_value = 0;
        switch (i) {
            case 0:
                decoded_value = flag_decode_1_deobf(flag_encoded[0], flag_chunk);
                break;
            case 1:
                decoded_value = flag_decode_2_deobf(flag_encoded[1], flag_chunk);
                break;
            case 2:
                decoded_value = flag_decode_3_deobf(flag_encoded[2], flag_chunk);
                break;
            case 3:
                decoded_value = flag_decode_4_deobf(flag_encoded[3], flag_chunk);
                break;
            case 4:
                decoded_value = flag_decode_5_deobf(flag_encoded[4], flag_chunk);
                break;
            case 5:
                decoded_value = flag_decode_6_deobf(flag_encoded[5], flag_chunk);
                break;
            case 6:
                decoded_value = flag_decode_7_deobf(flag_encoded[6], flag_chunk);
                break;
            case 7:
                decoded_value = flag_decode_7_deobf(flag_encoded[7], flag_chunk);
                break;
        }

        if (decoded_value != flag_cmp[i]) {
            is_valid = false;
            break;
        }
    }
    
    if (is_valid) {
        printf("Correct flag!\n");
    } else {
        printf("Incorrect flag!\n");
    }

    return 0;
}