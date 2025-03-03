// Single file sha256
// https://github.com/LekKit/sha256

#include <stdio.h>
#include <string.h>

namespace sha256 {

struct sha256_buff {
	unsigned long data_size;
	unsigned int h[8];
	unsigned char last_chunk[64];
	unsigned char chunk_size;
};

void sha256_init(struct sha256_buff* buff)
{
	buff->h[0] = 0x6a09e667;
	buff->h[1] = 0xbb67ae85;
	buff->h[2] = 0x3c6ef372;
	buff->h[3] = 0xa54ff53a;
	buff->h[4] = 0x510e527f;
	buff->h[5] = 0x9b05688c;
	buff->h[6] = 0x1f83d9ab;
	buff->h[7] = 0x5be0cd19;
	buff->data_size = 0;
	buff->chunk_size = 0;
}

static const unsigned int k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

#define rotate_r(val, bits) (val >> bits | val << (32 - bits))

static void sha256_calc_chunk(struct sha256_buff* buff, const unsigned char* chunk)
{
	unsigned int w[64];
	unsigned int tv[8];
	unsigned int i;

	for (i = 0; i < 16; ++i) {
		w[i] = (unsigned int) chunk[0] << 24 | (unsigned int) chunk[1] << 16
			| (unsigned int) chunk[2] << 8 | (unsigned int) chunk[3];
		chunk += 4;
	}

	for (i = 16; i < 64; ++i) {
		unsigned int s0 = rotate_r(w[i - 15], 7) ^ rotate_r(w[i - 15], 18) ^ (w[i - 15] >> 3);
		unsigned int s1 = rotate_r(w[i - 2], 17) ^ rotate_r(w[i - 2], 19) ^ (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}

	for (i = 0; i < 8; ++i)
		tv[i] = buff->h[i];

	for (i = 0; i < 64; ++i) {
		unsigned int S1 = rotate_r(tv[4], 6) ^ rotate_r(tv[4], 11) ^ rotate_r(tv[4], 25);
		unsigned int ch = (tv[4] & tv[5]) ^ (~tv[4] & tv[6]);
		unsigned int temp1 = tv[7] + S1 + ch + k[i] + w[i];
		unsigned int S0 = rotate_r(tv[0], 2) ^ rotate_r(tv[0], 13) ^ rotate_r(tv[0], 22);
		unsigned int maj = (tv[0] & tv[1]) ^ (tv[0] & tv[2]) ^ (tv[1] & tv[2]);
		unsigned int temp2 = S0 + maj;

		tv[7] = tv[6];
		tv[6] = tv[5];
		tv[5] = tv[4];
		tv[4] = tv[3] + temp1;
		tv[3] = tv[2];
		tv[2] = tv[1];
		tv[1] = tv[0];
		tv[0] = temp1 + temp2;
	}

	for (i = 0; i < 8; ++i)
		buff->h[i] += tv[i];
}

void sha256_update(struct sha256_buff* buff, const void* data, unsigned long size)
{
	const unsigned char* ptr = (const unsigned char*) data;
	buff->data_size += size;
	/* If there is data left in buff, concatenate it to process as new chunk */
	if (size + buff->chunk_size >= 64) {
		unsigned char tmp_chunk[64];
		memcpy(tmp_chunk, buff->last_chunk, buff->chunk_size);
		memcpy(tmp_chunk + buff->chunk_size, ptr, 64 - buff->chunk_size);
		ptr += (64 - buff->chunk_size);
		size -= (64 - buff->chunk_size);
		buff->chunk_size = 0;
		sha256_calc_chunk(buff, tmp_chunk);
	}
	/* Run over data chunks */
	while (size >= 64) {
		sha256_calc_chunk(buff, ptr);
		ptr += 64;
		size -= 64;
	}

	/* Save remaining data in buff, will be reused on next call or finalize */
	memcpy(buff->last_chunk + buff->chunk_size, ptr, size);
	buff->chunk_size += size;
}

void sha256_finalize(struct sha256_buff* buff)
{
	buff->last_chunk[buff->chunk_size] = 0x80;
	buff->chunk_size++;
	memset(buff->last_chunk + buff->chunk_size, 0, 64 - buff->chunk_size);

	/* If there isn't enough space to fit int64, pad chunk with zeroes and prepare next chunk */
	if (buff->chunk_size > 56) {
		sha256_calc_chunk(buff, buff->last_chunk);
		memset(buff->last_chunk, 0, 64);
	}

	/* Add total size as big-endian int64 x8 */
	unsigned long size = buff->data_size * 8;
	int i;
	for (i = 8; i > 0; --i) {
		buff->last_chunk[55 + i] = size & 255;
		size >>= 8;
	}

	sha256_calc_chunk(buff, buff->last_chunk);
}

void hash_it(const unsigned char* data, unsigned long data_size, unsigned char* hash)
{
	struct sha256_buff buff;
	sha256_init(&buff);
	sha256_update(&buff, data, data_size);
	sha256_finalize(&buff);
	for (int i = 0; i < 8; i++) {
		hash[i * 4] = (buff.h[i] >> 24) & 255;
		hash[i * 4 + 1] = (buff.h[i] >> 16) & 255;
		hash[i * 4 + 2] = (buff.h[i] >> 8) & 255;
		hash[i * 4 + 3] = buff.h[i] & 255;
	}
}

} // namespace sha256