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

#include <sys/time.h>
#include <err.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libgen.h>

#include "mmcrypt.h"

const char *
dump_hex(unsigned char *b, size_t blen)
{
	static size_t bhex_indbuf = 0;
	static char bhex_global[4 * 264];
	const size_t bhex_size = sizeof(bhex_global) / 4;
	char *bhex = &bhex_global[(bhex_indbuf++ % 4) * bhex_size];
	size_t i;

	if (blen * 2 + 1 > bhex_size)
		return NULL;
	for (i = 0; i < blen; i++) {
		snprintf(&bhex[0] + i * 2, bhex_size - i * 2, "%02X", (int)b[i]);
	}
	return bhex;
}

static void
benchmark_result(int iter, int c, int s,
    struct timeval *tstart, struct timeval *tend)
{
	const uintmax_t cells = (uintmax_t)(1ULL << (c + 1)) * s;
	const uintmax_t feedbacks = (uintmax_t)(1ULL << (2 * c)) * s /
	    MMCRYPT_FEEDBACK_RATE;
	const uintmax_t hashes = 1 + (4 + s + cells + feedbacks + 1) * iter;
	const uintmax_t mem = cells * (512 / 8) + s * sizeof(uint64_t);
        double t;

        t = tend->tv_sec - tstart->tv_sec;
        t += (double)(tend->tv_usec - tstart->tv_usec) / (double)1000000;
	printf("mmcrypt(%d, %d, %d): %jd cells, %jd hashes: %jd KB, %lf sec\n",
	    iter, c, s, cells, hashes, mem >> 10, t);
}

int
main(int argc, char **argv)
{
	struct mmcrypt_ctx ctx;
	struct timeval tstart, tend;
	unsigned char k1[512 / 8];
	unsigned char k2[512 / 8];
	int iter = 1, c = 7, s = 337;
	int rv = 0;

	switch (argc) {
	case 1:
		break;
	case 4:
		s = atoi(argv[3]);
		/* FALLTHROUGH */
	case 3:
		c = atoi(argv[2]);
		/* FALLTHROUGH */
	case 2:
		iter = atoi(argv[1]);
		if (iter != 0 && c != 0 && s != 0)
			break;
		/* FALLTHROUGH */
	default:
		fprintf(stderr, "usage: %s [iter] [c] [s]\n",
		    basename(argv[0]));
		return -1;
	}

	mmcrypt_init(&ctx);
	rv |= mmcrypt_absorb(&ctx, "pepper", strlen("pepper"));
	rv |= mmcrypt_absorb(&ctx, "salt", strlen("salt"));
	rv |= mmcrypt_absorb(&ctx, "tag", strlen("tag"));
	rv |= mmcrypt_absorb(&ctx, "password", strlen("password"));
	if (rv != 0)
		errx(1, "mmcrypt_absorb failed");

	gettimeofday(&tstart, NULL);
	rv |= mmcrypt_stretch(&ctx, iter, c, s);
	gettimeofday(&tend, NULL);
	if (rv != 0)
		errx(1, "mmcrypt_stretch failed");

	rv |= mmcrypt_squeeze(&ctx, k1, sizeof(k1));
	rv |= mmcrypt_squeeze(&ctx, k2, sizeof(k2));
	if (rv != 0)
		errx(1, "mmcrypt_squeeze failed");
	mmcrypt_destroy(&ctx);
	printf("mmcrypt(%d, %d, %d): k[0] = %s\n",
	    iter, c, s, dump_hex(k1, sizeof(k1)));
	printf("mmcrypt(%d, %d, %d): k[1] = %s\n",
	    iter, c, s, dump_hex(k2, sizeof(k2)));

	benchmark_result(iter, c, s, &tstart, &tend);

	return 0;
}
