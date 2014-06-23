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

#ifdef MMCRYPT_DEBUG
#include <stdio.h>
#endif

#define MMCRYPT_FRATE		65521

#define GF_POL1(n, p1) \
	(1ULL | (1ULL << p1))
#define GF_POL3(n, p1, p2, p3) \
	(1ULL | (1ULL << p1) | (1ULL << p2) | (1ULL << p3))
#define GF_POL5(n, p1, p2, p3, p4, p5) \
	(1ULL | (1ULL << p1) | (1ULL << p2) | (1ULL << p3) | (1ULL << p4) | (1ULL << p5))

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

static uint64_t
mmcrypt_gfmul(uint64_t x, uint64_t pol, uint64_t msb1)
{
	uint64_t carry;

	x = x << 1;
	carry = (uint64_t)(-(int64_t)!!(x & msb1));
	return (x ^ (pol & carry)) & (msb1 - 1);
}

static void
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

int
mmcrypt_stretch(struct mmcrypt_ctx *ctx, uint32_t iter, uint32_t c, uint32_t s)
{
	duplexState s1, s2, st;
	const int lbits = 512;
	const int lbytes = lbits / 8;
	const int lbytes64 = lbytes / 8;
	uint64_t feedback[lbytes64];
	uint8_t x[lbytes];
	uint64_t *t1, *t2, *x1, *x2;
	uint64_t xmask, match;
	uint64_t kpol, kmsb1, k0, k;
	uint32_t kmask, k1, k2, fcount;
	uint32_t sbytes, nsbytes;
	uint32_t rv, i, j, n;

#ifdef MMCRYPT_DEBUG
	uintmax_t d_hit, d_miss, d_feedback;
#endif

	if (iter < 1 || c < 1 || c > 31 || s < 1)
		return 1;
	n = 1 << c;
	if ((uint64_t)n * s * lbytes * 2 >= SIZE_MAX)
		return 1;
	sbytes = s * lbytes;
	nsbytes = n * sbytes;
	rv  = InitDuplex(&s1, 576, 1024);
	rv |= InitDuplex(&s2, 576, 1024);
	if (rv != 0)
		return 1;
	t1 = malloc(nsbytes * 2);
	if (t1 == NULL)
		return 1;
	t2 = t1 + nsbytes / 8;
#ifdef MMCRYPT_DEBUG
	printf("memory usage: %d kb\n", (nsbytes * 2) >> 10);
#endif
	memset(feedback, 0, sizeof(feedback));
	kpol = mmcrypt_gfpol[c];
	xmask = htobe64(((uint64_t)-1ULL) << (64 - c));
	kmask = (1 << c) - 1;
	for (; iter > 0; iter--) {
		Duplexing(&ctx->sm, NULL, 0, x, lbits);
		Duplexing(&s1, x, lbits, NULL, 0);
		Duplexing(&ctx->sm, NULL, 0, x, lbits);
		Duplexing(&s2, x, lbits, NULL, 0);
		Duplexing(&ctx->sm, NULL, 0, (uint8_t *)&k0, 64);
		k0 = be64toh(k0);
		k0 = k0 >> (64 - c * 2);
		kmsb1 = 1ULL << (c * 2);
		k0 |= (kmsb1 >> 1);
		fcount = 0;
#ifdef MMCRYPT_DEBUG
		d_hit = d_miss = d_feedback = 0;
#endif
		Duplexing(&s1, NULL, 0, (uint8_t *)t1, lbits);
		Duplexing(&s2, NULL, 0, (uint8_t *)t2, lbits);
		for (x1 = t1 + lbytes64, x2 = t2 + lbytes64; x1 < t2; x1 += lbytes64, x2 += lbytes64) {
			Duplexing(&s1, (uint8_t *)(x2 - lbytes64), lbits, (uint8_t *)x1, lbits);
			Duplexing(&s2, (uint8_t *)(x1 - lbytes64), lbits, (uint8_t *)x2, lbits);
		}
		k = k0;
		do {
			k = mmcrypt_gfmul(k, kpol, kmsb1);
			k1 = (k >> c) & kmask;
			k2 = k & kmask;
			x1 = t1 + sbytes * k1 / 8;
			x2 = t2 + sbytes * k2 / 8;
			match = (x1[0] ^ x2[0]) & xmask;
			match = -!!(int64_t)match;
#ifdef MMCRYPT_DEBUG
			if (match == 0) {
				d_hit++;
			} else {
				d_miss++;
			}
#endif
			for (i = 0; i < s; i++)
			{
				for (j = 0; j < lbytes64; j++) {
					feedback[j] ^= (x1[j] ^ x2[j]) & match;
				}
				mmcrypt_gfmul_512(feedback);
				if (++fcount == MMCRYPT_FRATE) {
					Duplexing(&ctx->sm, (uint8_t *)feedback, lbits, (uint8_t *)feedback, lbits);
					fcount = 0;
#ifdef MMCRYPT_DEBUG
					d_feedback++;
#endif
				}
			}
		} while (k != k0);
#ifdef MMCRYPT_DEBUG
		printf("iteration (%d) complete: %ju feedbacks, %ju lookups: %ju misses (%.2lf%%), %ju hits (%.2lf%%).\n",
			-iter, d_feedback, d_miss + d_hit,
			d_miss, (double)d_miss * 100 / (d_miss + d_hit),
			d_hit, (double)d_hit * 100 / (d_miss + d_hit));
		if (d_miss + d_hit != (1ULL << (c * 2)) - 1)
			abort();
#endif
		Duplexing(&ctx->sm, (uint8_t *)feedback, lbits, NULL, 0);
		/* Swap s1 and s2. */
		st = s2;
		s2 = s1;
		s1 = st;
	}
	memset(t1, 0, nsbytes * 2);
	free(t1);
	memset(x, 0, sizeof(x));
	memset(feedback, 0, sizeof(feedback));
	memset(&s1, 0, sizeof(s1));
	memset(&s2, 0, sizeof(s2));
	return 0;
}
