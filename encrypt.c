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
  a = inv(a);

  a= (0x63) ^
     (a) ^
     (a << 1) ^
     (a << 2) ^
     (a << 3) ^
     (a << 4) ^
     (a << 7) ^
     (a << 6) ^
     (a << 5) ^
     (a << 4);
  
  return a;
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

aes_gf28_t* xor(aes_gf28_t* arr1, aes_gf28_t* arr2) {
  aes_gf28_t* a = arr1;
  aes_gf28_t* b = arr2;
  aes_gf28_t* result = malloc(4);
  
  for (int i =0; i < 4; i++) {
    *result++ = *a++ ^ *b++;
  }

  return result;
}

void aes_enc_key_exp(aes_gf28_t* rk, aes_gf28_t* word, aes_gf28_t* rc) {
      //printf("%X", *rc++);

  //printf("\n");


  aes_gf28_t w[44][4];
  memcpy(w, word, sizeof(w));

  //aes_gf28_t* Rcon = rc;
  aes_gf28_t* temp = malloc(4);
  
  int i = 0;

  while (i < 4){
    aes_gf28_t t[4] = {rk[4*i], rk[4*i+1], rk[4*i+2], rk[4*i+3]};
    for (int x = 0; x < 4; x++) {
      w[i][x] = rk[4*i+x];
      printf("%X", w[i][x]);
    }
    printf("\n");
    i += 1;
  }

  i = 4;

  while (i < 44){
    for (int x = 0; x < 4; x++) {
      temp[x] = w[i-1][x];
      printf("%X", temp[x]);
    } printf("\n");
    if (i % 4 == 0) {
      rotWord(temp);
      for (int x = 0; x < 4; x++) {
        printf("%X", temp[x]);
      } printf("\n");
      subWord(temp);
      for (int x = 0; x < 4; x++) {
        printf("%X", temp[x]);
      } printf("\n");
      aes_gf28_t* x = xor(temp, rc[i/4]);
      *temp = *x;
    }
    aes_gf28_t* y = xor(&w[i-4], temp);
    *w[i] = *y;
    i += 1;
  }

  printf("key expansion: ");
  for (int i = 0; i < 44; i++) {
    printf("%X", w[i]);
  }
  
  //printf("\n");
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
  for (int i =0; i < 16; i++) {
    s[i] = s[i] ^ rk[i];
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

  aes_enc_rnd_key(s, w[0]);

  for (int i = 1; i < 10; i++) {
    aes_enc_rnd_sub(s);
    aes_enc_rnd_row(s);
    aes_enc_rnd_mix(s);
    aes_enc_rnd_key(s, rkp);
  }

  aes_enc_rnd_sub(s);
  aes_enc_rnd_row(s);
  aes_enc_rnd_mix(s);
  aes_enc_rnd_key(s, rkp);  

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

