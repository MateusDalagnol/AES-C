#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SHA256_BLOCK_SIZE 64

typedef uint8_t state_t[4][4];

typedef struct {
    uint8_t salt[16];
    uint8_t ciphertext[16];
} encrypted_t;

typedef struct {
    uint8_t salt[16];
    uint8_t iv[16];
    uint8_t *ciphertext;
    int tamanho
} encrypted_cbc_t;

const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16};

const uint8_t inv_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
    0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d};

const uint8_t rcon[14] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
                          0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D};

void print_state(state_t state, const char *titulo) {
    printf("\n%s:\n", titulo);
    printf("          Col0 Col1 Col2 Col3\n");
    for (int linha = 0; linha < 4; linha++) {
        printf("Linha %d:  ", linha);
        for (int col = 0; col < 4; col++) {
            printf(" %02x  ", state[linha][col]);
        }
        printf("\n");
    }
}

void print_keys(uint8_t *chaves, int num_palavras) {
    for (int p = 0; p < num_palavras; p++) {
        printf("Palavra %2d: ", p);
        for (int i = 0; i < 4; i++) {
            printf("%02x ", chaves[p * 4 + i]);
        }
        printf("\n");

        // A cada 4 palavras, mostra que é uma chave completa
        if ((p + 1) % 4 == 0) {
            printf("  ↑ Chave %d\n", (p + 1) / 4 - 1);
        }
    }
}

void print_hex(uint8_t *dados, int tamanho, const char *titulo) {
    printf("%s: ", titulo);
    for (int i = 0; i < tamanho; i++) {
        printf("%02x", dados[i]);
    }
    printf("\n");
}

void texto_para_state(uint8_t *texto, state_t state) {
    int idx = 0;

    for (int col = 0; col < 4; col++) {
        for (int linha = 0; linha < 4; linha++) {
            state[linha][col] = texto[idx++];
        }
    }
}

void state_para_texto(state_t state, uint8_t *texto) {
    int index = 0;
    for (int col = 0; col < 4; col++) {
        for (int linha = 0; linha < 4; linha++) {
            texto[index++] = state[linha][col];
        }
    }
}

void gerar_salt(uint8_t *salt) {
    for (int i = 0; i < 16; i++) {
        salt[i] = rand() % 256;
    }
}

uint8_t mul2(uint8_t x) {
    uint8_t resultado = x << 1;
    if (x & 0x80) {
        resultado ^= 0x1b;
    }

    return resultado;
}

uint8_t mul3(uint8_t x) { return mul2(x) ^ x; }

uint8_t mul4(uint8_t x) { return mul2(mul2(x)); }

uint8_t mul8(uint8_t x) { return mul2(mul4(x)); }

uint8_t mul9(uint8_t x) { return mul8(x) ^ x; }

uint8_t mul11(uint8_t x) { return mul8(x) ^ mul2(x) ^ x; }

uint8_t mul13(uint8_t x) { return mul8(x) ^ mul4(x) ^ x; }

uint8_t mul14(uint8_t x) { return mul8(x) ^ mul4(x) ^ mul2(x); }

void rot_word(uint8_t *palavra) {
    uint8_t temp = palavra[0];
    palavra[0] = palavra[1];
    palavra[1] = palavra[2];
    palavra[2] = palavra[3];
    palavra[3] = temp;
}

void sub_word(uint8_t *palavra) {
    for (int i = 0; i < 4; i++) {
        palavra[i] = sbox[palavra[i]];
    }
}

void sub_bytes(state_t state) {
    for (int linha = 0; linha < 4; linha++) {
        for (int col = 0; col < 4; col++) {
            // vai atribuir ao state o valor referenta na matriz sbox
            state[linha][col] = sbox[state[linha][col]];
        }
    }
}

void inv_sub_bytes(state_t state) {
    for (int linha = 0; linha < 4; linha++) {
        for (int col = 0; col < 4; col++) {
            state[linha][col] = inv_sbox[state[linha][col]];
        }
    }
}

void shift_rows(state_t state) {
    uint32_t linha;
    int deslocamento_bits;

    for (int linha_index = 0; linha_index < 4; linha_index++) {
        int deslocamento_bytes = linha_index;

        // converte de bytes para bits
        deslocamento_bits = deslocamento_bytes * 8;

        // vai juntar todas as possições em um unico uint32_t
        linha = (state[linha_index][0]) << 24 | (state[linha_index][1]) << 16 |
                (state[linha_index][2]) << 8 | state[linha_index][3];

        // desloca para a esquerda correspondente ao numero da linha
        if (deslocamento_bits > 0) {
            linha = (linha << deslocamento_bits) |
                    (linha >> (32 - deslocamento_bits));
        }

        // devolve os valores a matriz 4x4
        state[linha_index][0] = (linha >> 24) & 0xFF;
        state[linha_index][1] = (linha >> 16) & 0xFF;
        state[linha_index][2] = (linha >> 8) & 0xFF;
        state[linha_index][3] = linha & 0xFF;
    }
}

void inv_shift_rows(state_t state) {
    uint32_t linha;
    int deslocamento_bits;

    for (int linha_index = 0; linha_index < 4; linha_index++) {
        int deslocamento_bytes = linha_index;
        deslocamento_bits = deslocamento_bytes * 8;

        linha = (state[linha_index][0] << 24) | (state[linha_index][1] << 16) |
                (state[linha_index][2] << 8) | state[linha_index][3];

        if (deslocamento_bits > 0) {
            linha = (linha >> deslocamento_bits) |
                    (linha << (32 - deslocamento_bits));
        }

        state[linha_index][0] = (linha >> 24) & 0xFF;
        state[linha_index][1] = (linha >> 16) & 0xFF;
        state[linha_index][2] = (linha >> 8) & 0xFF;
        state[linha_index][3] = linha & 0xFF;
    }
}

void mix_columns(state_t state) {

    for (int col = 0; col < 4; col++) {

        // extrai uma coluna da matriz state
        uint8_t col0 = state[0][col];
        uint8_t col1 = state[1][col];
        uint8_t col2 = state[2][col];
        uint8_t col3 = state[3][col];

        // faz a tranformação
        uint8_t novo0 = mul2(col0) ^ mul3(col1) ^ col2 ^ col3;
        uint8_t novo1 = col0 ^ mul2(col1) ^ mul3(col2) ^ col3;
        uint8_t novo2 = col0 ^ col1 ^ mul2(col2) ^ mul3(col3);
        uint8_t novo3 = mul3(col0) ^ col1 ^ col2 ^ mul2(col3);

        // devolve o a coluna para a matrix
        state[0][col] = novo0;
        state[1][col] = novo1;
        state[2][col] = novo2;
        state[3][col] = novo3;
    }
}

void inv_mix_columns(state_t state) {
    for (int col = 0; col < 4; col++) {
        uint8_t a = state[0][col];
        uint8_t b = state[1][col];
        uint8_t c = state[2][col];
        uint8_t d = state[3][col];

        state[0][col] = mul14(a) ^ mul11(b) ^ mul13(c) ^ mul9(d);
        state[1][col] = mul9(a) ^ mul14(b) ^ mul11(c) ^ mul13(d);
        state[2][col] = mul13(a) ^ mul9(b) ^ mul14(c) ^ mul11(d);
        state[3][col] = mul11(a) ^ mul13(b) ^ mul9(c) ^ mul14(d);
    }
}

void add_round_key(state_t state, uint8_t *round_key) {
    for (int col = 0; col < 4; col++) {
        for (int linha = 0; linha < 4; linha++) {
            state[linha][col] ^= round_key[linha + col * 4];
        }
    }
}

void key_expansion_256(uint8_t *chave, uint8_t *chaves_expandidas) {

    for (int i = 0; i < 32; i++) {
        chaves_expandidas[i] = chave[i];
    }

    int palavras_geradas = 8;
    int rcon_index = 0;

    while (palavras_geradas < 60) {

        uint8_t temp[4];
        int ultimo_indice = (palavras_geradas - 1) * 4;

        for (int i = 0; i < 4; i++) {
            temp[i] = chaves_expandidas[ultimo_indice + i];
        }

        if (palavras_geradas % 8 == 0) {
            rot_word(temp);
            sub_word(temp);

            temp[0] ^= rcon[rcon_index];
            rcon_index++;
        } else if (palavras_geradas % 8 == 4) {
            sub_word(temp);
        }

        int indice_antigo = (palavras_geradas - 8) * 4;
        int indice_novo = palavras_geradas * 4;

        for (int i = 0; i < 4; i++) {
            chaves_expandidas[indice_novo + i] =
                chaves_expandidas[indice_antigo + i] ^ temp[i];
        }

        palavras_geradas++;
    }
}

void aes_256(uint8_t *texto, uint8_t *chave, uint8_t *cifrado) {
    state_t state;
    uint8_t chaves_expandidas[240];

    texto_para_state(texto, state);
    key_expansion_256(chave, chaves_expandidas);

    add_round_key(state, chaves_expandidas);

    for (int rodada = 1; rodada <= 13; rodada++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, chaves_expandidas + (rodada * 16));
    }

    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, chaves_expandidas + (14 * 16));

    state_para_texto(state, cifrado);
}

void aes_256_decrypt(uint8_t *cifrado, uint8_t *chave, uint8_t *texto) {
    state_t state;
    uint8_t chaves_expandidas[240];

    texto_para_state(cifrado, state);
    key_expansion_256(chave, chaves_expandidas);

    add_round_key(state, chaves_expandidas + (14 * 16));

    for (int rodada = 13; rodada >= 1; rodada--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, chaves_expandidas + (rodada * 16));
        inv_mix_columns(state);
    }

    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, chaves_expandidas);

    state_para_texto(state, texto);
}

void sha_256(uint8_t *chave, int chave_len, uint8_t *dados, int dados_len,
             uint8_t *saida) {
    uint8_t k_ipad[SHA256_BLOCK_SIZE];
    uint8_t k_opad[SHA256_BLOCK_SIZE];
    uint8_t inner_hash[SHA256_DIGEST_LENGTH];
    uint8_t k[SHA256_BLOCK_SIZE];
    int i;

    if (chave_len > SHA256_BLOCK_SIZE) {
        SHA256(chave, chave_len, k);
        memcpy(k, k, SHA256_DIGEST_LENGTH);
        chave_len = SHA256_DIGEST_LENGTH;
    } else {
        memcpy(k, chave, chave_len);
    }

    for (i = chave_len; i < SHA256_BLOCK_SIZE; i++) {
        k[i] = 0;
    }

    for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
        k_ipad[i] = k[i] ^ 0x36;
        k_opad[i] = k[i] ^ 0x5C;
    }

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, k_ipad, SHA256_BLOCK_SIZE);
    SHA256_Update(&ctx, dados, dados_len);
    SHA256_Final(inner_hash, &ctx);

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, k_opad, SHA256_BLOCK_SIZE);
    SHA256_Update(&ctx, inner_hash, SHA256_DIGEST_LENGTH);
    SHA256_Final(saida, &ctx);
}

void pbkdf2(uint8_t *senha, int senha_len, uint8_t *salt, int salt_len,
            int iteracoes, uint8_t *chave, int chave_len) {
    uint8_t u[SHA256_DIGEST_LENGTH];
    uint8_t t[SHA256_DIGEST_LENGTH];
    uint8_t salt_bloco[64];

    int blocos = (chave_len + SHA256_DIGEST_LENGTH - 1) / SHA256_DIGEST_LENGTH;
    int i, j, k;

    for (int bloco = 1; bloco <= blocos; bloco++) {
        memcpy(salt_bloco, salt, salt_len);
        salt_bloco[salt_len] = (bloco >> 24) & 0xFF;
        salt_bloco[salt_len + 1] = (bloco >> 16) & 0xFF;
        salt_bloco[salt_len + 2] = (bloco >> 8) & 0xFF;
        salt_bloco[salt_len + 3] = bloco & 0xFF;

        sha_256(senha, senha_len, salt_bloco, salt_len + 4, u);
        memcpy(t, u, SHA256_DIGEST_LENGTH);

        for (i = 1; i < iteracoes; i++) {
            sha_256(senha, senha_len, u, SHA256_DIGEST_LENGTH, u);
            for (j = 0; j < SHA256_DIGEST_LENGTH; j++) {
                t[j] ^= u[j];
            }
        }

        int offset = (bloco - 1) * SHA256_DIGEST_LENGTH;
        int tamanho = (chave_len - offset) > SHA256_DIGEST_LENGTH
                          ? SHA256_DIGEST_LENGTH
                          : (chave_len - offset);
        memcpy(chave + offset, t, tamanho);
    }
}

void derivar_chave_de_senha(uint8_t *senha, uint8_t *salt, uint8_t *chave) {
    pbkdf2(senha, strlen((char *)senha), salt, 16, 100000, chave, 32);
}

encrypted_t criptografar(uint8_t *texto, uint8_t *senha){
    encrypted_t resultado;
    uint8_t chave[32];

    gerar_salt(resultado.salt);

    derivar_chave_de_senha(senha, resultado.salt, chave);

    aes_256(texto, chave, resultado.ciphertext);

    return resultado;
}

int decodificar(encrypted_t *entrada, uint8_t *senha, uint8_t *texto){
    uint8_t chave[32];

    derivar_chave_de_senha(senha, entrada->salt, chave);
    aes_256_decrypt(entrada->ciphertext, chave, texto);

    return 1;
}

void criptografar_cbc(uint8_t *texto, int tamanho, 
                       uint8_t *senha, uint8_t *salt,
                       uint8_t *cifrado, uint8_t *iv) {
    
    uint8_t chave[32];
    uint8_t bloco[16];
    uint8_t anterior[16];
    uint8_t cifrado_bloco[16];
    
    derivar_chave_de_senha(senha, salt, chave);
    
    for (int i = 0; i < 16; i++) {
        iv[i] = rand() % 256;
    }
    
    memcpy(anterior, iv, 16);
    
    for (int i = 0; i < tamanho; i += 16) {
        int bloco_tamanho = (tamanho - i) < 16 ? (tamanho - i) : 16;
        memcpy(bloco, texto + i, bloco_tamanho);
        
        if (bloco_tamanho < 16) {
            memset(bloco + bloco_tamanho, 0, 16 - bloco_tamanho);
        }
        
        for (int j = 0; j < 16; j++) {
            bloco[j] ^= anterior[j];
        }
        
        aes_256(bloco, chave, cifrado_bloco);
        memcpy(cifrado + i, cifrado_bloco, 16);
        memcpy(anterior, cifrado_bloco, 16);
    }
}

void decodificar_cbc(uint8_t *cifrado, int tamanho,
                       uint8_t *senha, uint8_t *salt, uint8_t *iv,
                       uint8_t *texto) {
    
    uint8_t chave[32];
    uint8_t bloco[16];
    uint8_t anterior[16];
    uint8_t texto_bloco[16];
    
    derivar_chave_de_senha(senha, salt, chave);
    memcpy(anterior, iv, 16);
    
    for (int i = 0; i < tamanho; i += 16) {
        memcpy(bloco, cifrado + i, 16);
        
        aes_256_decrypt(bloco, chave, texto_bloco);
        
        for (int j = 0; j < 16; j++) {
            texto_bloco[j] ^= anterior[j];
        }
        
        memcpy(texto + i, texto_bloco, 16);
        memcpy(anterior, bloco, 16);
    }
}

encrypted_cbc_t criptografar_texto_grande(uint8_t *texto, int tamanho, uint8_t *senha) {
    encrypted_cbc_t resultado;
    
    int blocos = (tamanho + 15) / 16;
    resultado.ciphertext = malloc(blocos * 16);
    resultado.tamanho = blocos * 16;
    
    gerar_salt(resultado.salt);
    
    criptografar_cbc(texto, tamanho, senha, resultado.salt, 
                      resultado.ciphertext, resultado.iv);
    
    return resultado;
}

void decodificar_texto_grande(encrypted_cbc_t *entrada, uint8_t *senha, uint8_t *texto) {
    decodificar_cbc(entrada->ciphertext, entrada->tamanho, 
                     senha, entrada->salt, entrada->iv, texto);
}

int main() {
    srand(time(NULL));
    int opcao;
    char senha_input[100];
    char texto_input[4096];
    char cifrado_hex[8192];
    uint8_t texto_bytes[4096];
    uint8_t senha_bytes[100];
    uint8_t salt[16];
    uint8_t iv[16];
    uint8_t *cifrado_bytes;
    uint8_t texto_decifrado[4096];
    int tamanho, tamanho_cifrado;

    do {
        printf("Escolha uma opcao:\n");
        printf("1 - Criptografar texto\n");
        printf("2 - Descriptografar texto\n");
        printf("0 - Sair\n");
        printf("Opcao: ");
        scanf("%d", &opcao);
        getchar();
        
        if (opcao == 1) {
            
            printf("Digite a senha: ");
            fgets(senha_input, sizeof(senha_input), stdin);
            senha_input[strcspn(senha_input, "\n")] = 0;
            memcpy(senha_bytes, senha_input, strlen(senha_input));
            
            printf("Digite o texto a ser criptografado: ");
            fgets(texto_input, sizeof(texto_input), stdin);
            texto_input[strcspn(texto_input, "\n")] = 0;
            tamanho = strlen(texto_input);
            memcpy(texto_bytes, texto_input, tamanho);
            
            encrypted_cbc_t resultado = criptografar_texto_grande(texto_bytes, tamanho, senha_bytes);

            printf("Salt: ");
            for (int i = 0; i < 16; i++) printf("%02x", resultado.salt[i]);
            printf("\n");
            
            printf("IV: ");
            for (int i = 0; i < 16; i++) printf("%02x", resultado.iv[i]);
            printf("\n");
            
            printf("Cifrado: ");
            for (int i = 0; i < resultado.tamanho; i++) printf("%02x", resultado.ciphertext[i]);
            printf("\n\n");
            
            free(resultado.ciphertext);
        }
        else if (opcao == 2) {

            printf("Digite a senha: ");
            fgets(senha_input, sizeof(senha_input), stdin);
            senha_input[strcspn(senha_input, "\n")] = 0;
            memcpy(senha_bytes, senha_input, strlen(senha_input));
            
            printf("Digite o Salt (32 caracteres hex): ");
            fgets(cifrado_hex, sizeof(cifrado_hex), stdin);
            cifrado_hex[strcspn(cifrado_hex, "\n")] = 0;
            for (int i = 0; i < 16; i++) {
                sscanf(cifrado_hex + (i * 2), "%02hhx", &salt[i]);
            }
            
            printf("Digite o IV (32 caracteres hex): ");
            fgets(cifrado_hex, sizeof(cifrado_hex), stdin);
            cifrado_hex[strcspn(cifrado_hex, "\n")] = 0;
            for (int i = 0; i < 16; i++) {
                sscanf(cifrado_hex + (i * 2), "%02hhx", &iv[i]);
            }
            
            printf("Digite o texto cifrado (em hex): ");
            fgets(cifrado_hex, sizeof(cifrado_hex), stdin);
            cifrado_hex[strcspn(cifrado_hex, "\n")] = 0;
            
            tamanho_cifrado = strlen(cifrado_hex) / 2;
            cifrado_bytes = malloc(tamanho_cifrado);
            for (int i = 0; i < tamanho_cifrado; i++) {
                sscanf(cifrado_hex + (i * 2), "%02hhx", &cifrado_bytes[i]);
            }

            decodificar_cbc(cifrado_bytes, tamanho_cifrado, senha_bytes, salt, iv, texto_decifrado);
            texto_decifrado[tamanho_cifrado] = '\0';
            
            printf("Texto decifrado: %s\n\n", texto_decifrado);
            
            free(cifrado_bytes);
        }
        else if (opcao != 0) {
            printf("\nOpcao invalida!\n\n");
        }
        
    } while (opcao != 0);
    
    printf("\nEncerrando...\n");
    return 0;
}