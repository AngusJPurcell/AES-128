/* Copyright (C) 2018 Daniel Page <csdsp@bristol.ac.uk>
 *
 * Use of this source code is restricted per the CC BY-NC-ND license, a copy of 
 * which can be found via http://creativecommons.org (and should be included as 
 * LICENSE.txt within the associated archive or repository).
 */

#include "encrypt.h"

typedef uint8_t aes_gf28_t;

aes_gf28_t xtime(aes_gf28_t a) {
  if((a & 0x80) == 0x80) {
    return 0x1B ^ (a << 1);
  } else {
    return (a << 1);
  }
}

aes_gf28_t mul(aes_gf28_t a, aes_gf28_t b) {

  aes_gf28_t t =0;

  for (int i = 7; i >= 0; i--) {

    t = xtime(t);

    if((b >> i) & 1) {
      t ^= a;
    }
  }

  return t;
}

aes_gf28_t inv(aes_gf28_t a) {

  aes_gf28_t t0 = mul(a, a);
  aes_gf28_t t1 = mul(t0, a);
             t0 = mul(t0, t0);
             t1 = mul(t1, t0);
             t0 = mul(t0, t0);
             t0 = mul(t1, t0);
             t0 = mul(t0, t0);
             t0 = mul(t0, t0);
             t1 = mul(t1, t0);
             t0 = mul(t0, t1);
             t0 = mul(t0, t0);

  return t0;
}

aes_gf28_t sbox(aes_gf28_t a) {
  aes_gf28_t sbox[256] = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

  return sbox[a];
}

void copy(aes_gf28_t* s, uint8_t* m) {
  for (int i = 0; i < 16; i++) {
    s[i] = m[i];
  }
}

void subWord(aes_gf28_t* word) {
  for (int i = 0; i < 4; i++) {
    word[i] = sbox(word[i]);
  }
}

void  rotWord(aes_gf28_t* word) {
  aes_gf28_t temp = word[0];
  for (int i = 0; i < 4; i++) {
    word[i] = word[i+1];
  }
  word[3] = temp;
}

void xor(aes_gf28_t* arr1, aes_gf28_t* arr2) {
  aes_gf28_t* a = arr1;
  aes_gf28_t* b = arr2;

  for (int i =0; i < 4; i++) {
    *a = *a ^ *b;
    *a++; *b++;
  }
  
}

void aes_enc_key_exp(aes_gf28_t* rk, aes_gf28_t* word, aes_gf28_t* rc) {

  aes_gf28_t w[44][4];
  memcpy(w, word, sizeof(w));

  aes_gf28_t rcon[10][4];
  memcpy(rcon, rc, sizeof(rcon));

  aes_gf28_t* temp = malloc(4);
  
  int i = 0;

  while (i < 4){
    for (int x = 0; x < 4; x++) {
      w[i][x] = rk[4*i+x];
    }
    i += 1;
  }

  i = 4;

  while (i < 44){
    for (int x = 0; x < 4; x++) {
      temp[x] = w[i-1][x];
    }
    
    if (i % 4 == 0) {
      rotWord(temp);

      subWord(temp);

      xor(temp, *((rcon + i/4) -1));

    }

    xor(temp, *(w + i - 4));
    
    for (int x = 0; x < 4; x++) {
      w[i][x] = temp[x];
    }
    i += 1;
  }

  printf("key expansion: \n");
  for (int i = 0; i < 44; i++) {
    printf("%d: ", i);
    for (int j = 0; j < 4; j++) {
      printf("%02x", w[i][j]);
    } 
    printf("\n");
  }
  
  memcpy(word, w, sizeof(w));
}

void aes_enc_rnd_sub(aes_gf28_t* s) {
  //printf("sub: ");
  for (int i = 0; i < 16; i++) {
    s[i] = sbox(s[i]);
  }
  for (int i = 0; i < 16; i++) {
      //printf("%x, ", s[i]);
  }
  //printf("\n");
}

#define RND_ROW_STEP(a, b, c, d, e, f, g, h) {\
  aes_gf28_t a1 = s[a];                       \
  aes_gf28_t b1 = s[b];                       \
  aes_gf28_t c1 = s[c];                       \
  aes_gf28_t d1 = s[d];                       \
                                              \
  s[e] = a1;                                  \
  s[f] = b1;                                  \
  s[g] = c1;                                  \
  s[h] = d1;                                  \
}

void aes_enc_rnd_row(aes_gf28_t* s) {
  RND_ROW_STEP(1, 5, 9, 13, 13, 1, 5, 9);
  RND_ROW_STEP(2, 6, 10, 14, 10, 14, 2, 6);
  RND_ROW_STEP(3, 7, 11, 15, 7, 11, 15, 3);

  //printf("row: ");
  for (int i = 0; i < 16; i++) {
      //printf("%x, ", s[i]);
  }
  //printf("\n");
}

#define RND_MIX_STEP(a, b, c, d) {\
  aes_gf28_t a1 = s[a];     \
  aes_gf28_t b1 = s[b];     \
  aes_gf28_t c1 = s[c];     \
  aes_gf28_t d1 = s[d];     \
                            \
  aes_gf28_t a2 = xtime(a1);\
  aes_gf28_t b2 = xtime(b1);\
  aes_gf28_t c2 = xtime(c1);\
  aes_gf28_t d2 = xtime(d1);\
                            \
  aes_gf28_t a3 = a1 ^ a2;  \
  aes_gf28_t b3 = b1 ^ b2;  \
  aes_gf28_t c3 = c1 ^ c2;  \
  aes_gf28_t d3 = d1 ^ d2;  \
                            \
  s[ a ] = a2 ^ b3 ^ c1 ^ d1; \
  s[ b ] = a1 ^ b2 ^ c3 ^ d1; \
  s[ c ] = a1 ^ b1 ^ c2 ^ d3; \
  s[ d ] = a3 ^ b1 ^ c1 ^ d2; \
}

void aes_enc_rnd_mix(aes_gf28_t* s) {
  RND_MIX_STEP ( 0, 1, 2, 3 );
  RND_MIX_STEP ( 4, 5, 6, 7 );
  RND_MIX_STEP ( 8, 9, 10, 11 );
  RND_MIX_STEP ( 12, 13, 14, 15 );
}

void aes_enc_rnd_key(aes_gf28_t* s, const aes_gf28_t* rk) {
  for (int i = 0; i < 4; i++) {
    s[i*4] = s[i*4] ^ *rk++;
    s[i*4+1] = s[i*4+1] ^ *rk++;
    s[i*4+2] = s[i*4+2] ^ *rk++;
    s[i*4+3] = s[i*4+3] ^ *rk++;
  }
}

void aes_enc(uint8_t* c, uint8_t* m, uint8_t* k) {
  uint8_t rc[10][4] = {{0x01, 0x00, 0x00, 0x00},
                      {0x02, 0x00, 0x00, 0x00},
                      {0x04, 0x00, 0x00, 0x00},
                      {0x08, 0x00, 0x00, 0x00},
                      {0x10, 0x00, 0x00, 0x00},
                      {0x20, 0x00, 0x00, 0x00},
                      {0x40, 0x00, 0x00, 0x00},
                      {0x80, 0x00, 0x00, 0x00},
                      {0x1b, 0x00, 0x00, 0x00},
                      {0x36, 0x00, 0x00, 0x00}};

  aes_gf28_t rk[16], s[16];

  aes_gf28_t* rcp = rc;
  aes_gf28_t* rkp = rk;

  aes_gf28_t w[44][4];

  copy(s, m);
  copy(rkp, k);

  aes_enc_key_exp(rkp, *w, *rc);
  printf("key expansion: %d\n", 10);

  aes_gf28_t* rkey[44];
  aes_gf28_t* roundkey[11];
  for (int i = 0; i < 44; i++) {
    rkey[i] = (w[i][0]<<24) | (w[i][1]<<16)| (w[i][2]<<8) | w[i][3];
  }
  for (int i = 0; i < 11; i++) {
    roundkey[i] = ((aes_gf28_t)rkey[i*4]<<24) | ((aes_gf28_t)rkey[i*4+1]<<16)| ((aes_gf28_t)rkey[i*4+2]<<8) | (aes_gf28_t)rkey[i*4+3];
    printf("%x\n", roundkey[i]);
  }
  printf("key expansion: %d\n", 10);


  aes_enc_rnd_key(s, *rkey);
  printf("key expansion: %d\n", 10);

  for (int i = 1; i < 10; i++) {
    aes_enc_rnd_sub(s);
    aes_enc_rnd_row(s);
    aes_enc_rnd_mix(s);
    aes_enc_rnd_key(s, *rkey);
  }

  aes_enc_rnd_sub(s);
  aes_enc_rnd_row(s);
  aes_enc_rnd_mix(s);
  aes_enc_rnd_key(s, *rkey);  

  copy(c, s);
}

int main( int argc, char* argv[] ) {
  uint8_t k[ 16 ] = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
                      0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C };
  uint8_t m[ 16 ] = { 0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D,
                      0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34 };
  uint8_t c[ 16 ] = { 0x39, 0x25, 0x84, 0x1D, 0x02, 0xDC, 0x09, 0xFB,
                      0xDC, 0x11, 0x85, 0x97, 0x19, 0x6A, 0x0B, 0x32 };
  uint8_t t[ 16 ];

  //AES_KEY rk;

  //AES_set_encrypt_key( k, 128, &rk );
  // AES_encrypt( m, t, &rk );  

  aes_enc(t, m, k);

  if( !memcmp( t, c, 16 * sizeof( uint8_t ) ) ) {
    printf( "AES.Enc( k, m ) == c\n" );
    for (int i = 0; i < 16; i++) {
      printf("%x, ", t[i]);
    }
    printf("\n");
    for (int i = 0; i < 16; i++) {
      printf("%x, ", c[i]);
    }
  }
  else {
    printf( "AES.Enc( k, m ) != c\n" );
    for (int i = 0; i < 16; i++) {
      printf("%x, ", t[i]);
    }
    printf("\n");
    for (int i = 0; i < 16; i++) {
      printf("%x, ", c[i]);
    }
    printf("\n");
  }
  //k: 2b7e151628aed2a6abf7158809cf4f3c
  //m: 3253f6a8885a308d313198a2e0370734
  //Nk: 4, Nb: 4, Nr: 10
  return 0;
}

