/*-
 * Author: Gleb Kurtsou <gleb@FreeBSD.org>
 *
 * This software is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#if defined(__linux__)
#include <endian.h>
#elif defined(__FreeBSD__)
#include <sys/endian.h>
#endif
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "mmcrypt.h"

#define L_BITS			(512)
#define L_BYTES			(L_BITS / 8)
#define L_QUADS			(L_BYTES / 8)

#define GF_POL1(n, p1) \
	(1ULL | (1ULL << p1))
#define GF_POL3(n, p1, p2, p3) \
	(1ULL | (1ULL << p1) | (1ULL << p2) | (1ULL << p3))
#define GF_POL5(n, p1, p2, p3, p4, p5) \
	(1ULL | (1ULL << p1) | (1ULL << p2) | (1ULL << p3) | \
	    (1ULL << p4) | (1ULL << p5))

static const uint64_t mmcrypt_gfpol[] =
{
	0,
	GF_POL1(2, 1),
	GF_POL1(4, 1),
	GF_POL3(6, 1, 4, 5),
	GF_POL5(8, 2, 4, 5, 6, 7),
	GF_POL5(10, 1, 2, 5, 6, 7),
	GF_POL5(12, 2, 6, 8, 9, 10),
	GF_POL5(14, 1, 3, 4, 5, 11),
	GF_POL5(16, 2, 9, 12, 13, 14),
	GF_POL5(18, 1, 4, 7, 8, 10),
	GF_POL5(20, 1, 10, 14, 16, 18),
	GF_POL5(22, 2, 4, 9, 14, 21),
	GF_POL5(24, 3, 6, 7, 16, 23),
	GF_POL5(26, 1, 6, 15, 17, 24),
	GF_POL5(28, 5, 11, 21, 24, 27),
	GF_POL5(30, 11, 12, 24, 28, 29),
	GF_POL5(32, 1, 3, 12, 17, 30),
	GF_POL5(34, 4, 7, 14, 20, 31),
	GF_POL5(36, 6, 17, 25, 26, 28),
	GF_POL5(38, 6, 9, 11, 20, 36),
	GF_POL5(40, 6, 7, 18, 28, 36),
	GF_POL5(42, 1, 8, 14, 24, 27),
	GF_POL5(44, 5, 16, 25, 40, 43),
	GF_POL5(46, 21, 23, 24, 40, 44),
	GF_POL5(48, 5, 12, 27, 29, 43),
	GF_POL5(50, 5, 6, 16, 21, 36),
	GF_POL5(52, 1, 2, 16, 25, 50),
	GF_POL5(54, 9, 10, 23, 24, 34),
	GF_POL5(56, 5, 20, 28, 38, 45),
	GF_POL5(58, 23, 32, 37, 54, 55),
	GF_POL5(60, 12, 13, 19, 31, 48),
	GF_POL5(62, 2, 9, 16, 18, 48),
};

void
mmcrypt_init(struct mmcrypt_ctx *ctx)
{
	int rv;

	rv = InitDuplex(&ctx->sm, 576, 1024);
	if (rv != 0)
		abort();
}

void
mmcrypt_destroy(struct mmcrypt_ctx *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
}

int
mmcrypt_absorb(struct mmcrypt_ctx *ctx, const void *data, size_t datalen)
{
	int rv;

	rv = Duplexing(&ctx->sm, data, datalen * 8, NULL, 0);
	return !!rv;
}

int
mmcrypt_squeeze(struct mmcrypt_ctx *ctx, void *key, size_t keylen)
{
	int rv;

	rv = Duplexing(&ctx->sm, NULL, 0, key, keylen * 8);
	return !!rv;
}

static inline uint64_t
mmcrypt_gfmul(uint64_t x, uint64_t pol, uint64_t msb1)
{
	uint64_t carry;

	x = x << 1;
	carry = (uint64_t)(-(int64_t)!!(x & msb1));
	return (x ^ (pol & carry)) & (msb1 - 1);
}

static inline void
mmcrypt_gfmul_512(uint64_t *x)
{
	// 512,8,5,2
	static const int gf_512_pol = 0x125;
	int i, msb;
	uint8_t c;

	msb = x[0] >> 63;
	for (i = 0; i < 7; i++) {
		c = x[i + 1] >> 63;
		x[i] = (x[i] << 1) | c;
	}
	x[7] = (x[7] << 1) ^ ((-msb) & gf_512_pol);
}

static inline uint32_t
mmcrypt_wrap(uint64_t *x, uint32_t i, uint32_t imask)
{
	uint64_t a;
	uint32_t w;

	a = be64toh(x[L_QUADS - 1]);
	w = a & imask;
	w += i - imask - 1;
	return w;
}

static inline void
mmcrypt_mix(uint64_t *feedback, uint64_t xmask,
    uint64_t *x1, uint64_t *x2,
    uint64_t *y1, uint64_t *y2)
{
	uint64_t x[L_QUADS];
	uint64_t xswap, xskip;
	uint64_t t;
	uint32_t j;

	xskip = (x1[0] ^ x2[0]) & xmask;
	xskip = -!!(int64_t)(xskip & xmask);
	for (j = 0; j < L_QUADS; j++) {
		x[j] = x1[j] ^ x2[j];
		feedback[j] ^= x[j] & xskip;
	}
	mmcrypt_gfmul_512(feedback);
	xswap = -(int64_t)(((uint8_t *)feedback)[0] >> 7);

	mmcrypt_gfmul_512(x);
	for (j = 0; j < L_QUADS; j++) {
		t = (y1[j] ^ y2[j] ^ x[j]) & xswap;
		y1[j] ^= t;
		y2[j] ^= t;
	}
}

int
mmcrypt_stretch(struct mmcrypt_ctx *ctx, uint32_t iter, uint32_t c, uint32_t s)
{
	duplexState s1, s2, st;
	uint64_t feedback[L_QUADS];
	uint64_t x[L_QUADS];
	uint64_t *k, *t1, *t2, *x1, *x2;
	uint64_t xmask;
	uint64_t k0, kpol, kmsb1;
	size_t nsbytes;
	uint32_t kmask, ka, kb;
	uint32_t feedback_count;
	uint32_t i, imask, n, rv;

	if (iter < 1 || c < 1 || c > 31 || s < 1)
		return 1;
	n = 1 << c;
	if ((uint64_t)n * s * L_BYTES * 2 + s * sizeof(k[0]) >= SIZE_MAX)
		return 1;
	nsbytes = n * s * L_BYTES;
	rv  = InitDuplex(&s1, 576, 1024);
	rv |= InitDuplex(&s2, 576, 1024);
	if (rv != 0)
		return 1;
	k = malloc(s * sizeof(k[0]) + nsbytes * 2);
	if (k == NULL)
		return 1;
	t1 = &k[s];
	t2 = &t1[nsbytes / sizeof(t1[0])];
	memset(feedback, 0, sizeof(feedback));
	kpol = mmcrypt_gfpol[c];
	kmsb1 = 1ULL << (c * 2);
	kmask = (1 << c) - 1;
	xmask = htobe64(((uint64_t)-1ULL) << (64 - c));
	x[0] = htobe64(MMCRYPT_FEEDBACK_RATE);
	x[1] = htobe64(iter);
	x[2] = htobe64(c);
	x[3] = htobe64(s);
	x[4] = htobe64(0);
	x[5] = htobe64(0);
	x[6] = htobe64(0);
	x[7] = htobe64(0);
	Duplexing(&ctx->sm, (uint8_t *)x, L_BITS, NULL, 0);
	for (; iter > 0; iter--) {
		Duplexing(&ctx->sm, NULL, 0, (uint8_t *)x, L_BITS);
		Duplexing(&s1, (uint8_t *)x, L_BITS, NULL, 0);
		Duplexing(&ctx->sm, NULL, 0, (uint8_t *)x, L_BITS);
		Duplexing(&s2, (uint8_t *)x, L_BITS, NULL, 0);
		for (i = 0; i < s; i++) {
			Duplexing(&ctx->sm, NULL, 0, (uint8_t *)&k[i], 64);
			k[i] = be64toh(k[i]);
			k[i] = k[i] >> (64 - c * 2);
			k[i] |= 1;
		}
		feedback_count = 0;
		Duplexing(&s1, NULL, 0, (uint8_t *)t1, L_BITS);
		Duplexing(&s2, NULL, 0, (uint8_t *)t2, L_BITS);
		for (i = 1, imask = 0, x1 = t1 + L_QUADS, x2 = t2 + L_QUADS;
		    x1 < t2; x1 += L_QUADS, x2 += L_QUADS, i++) {
			imask |= i >> 1;
			ka = mmcrypt_wrap(x2 - L_QUADS, i, imask);
			kb = mmcrypt_wrap(x1 - L_QUADS, i, imask);
			Duplexing(&s1, (uint8_t *)(t2 + ka * L_QUADS), L_BITS,
			    (uint8_t *)x1, L_BITS);
			Duplexing(&s2, (uint8_t *)(t1 + kb * L_QUADS), L_BITS,
			    (uint8_t *)x2, L_BITS);
		}
		k0 = k[0];
		do {
			for (i = 0; i < s; i++) {
				k[i] = mmcrypt_gfmul(k[i], kpol, kmsb1);
				ka = (k[i] >> c) & kmask;
				kb = k[i] & kmask;
				mmcrypt_mix(feedback, xmask,
				    &t1[(ka * s + i) * L_QUADS],
				    &t2[(kb * s + i) * L_QUADS],
				    &t1[(ka * s + (i + 1) % s) * L_QUADS],
				    &t2[(kb * s + (i + 1) % s) * L_QUADS]);
				if (++feedback_count == MMCRYPT_FEEDBACK_RATE) {
					feedback_count = 0;
					Duplexing(&ctx->sm,
					    (uint8_t *)feedback, L_BITS,
					    (uint8_t *)feedback, L_BITS);
				}
			}
		} while (k0 != k[0]);
		Duplexing(&ctx->sm, (uint8_t *)feedback, L_BITS, NULL, 0);
		st = s1;
		s1 = s2;
		s2 = st;
	}
	// TODO Use memset_s if available
	memset(k, 0, s * sizeof(k[0]) + nsbytes * 2);
	free(k);
	memset(x, 0, sizeof(x));
	memset(feedback, 0, sizeof(feedback));
	memset(&s1, 0, sizeof(s1));
	memset(&s2, 0, sizeof(s2));
	return 0;
}
