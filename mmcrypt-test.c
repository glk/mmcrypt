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

#include <err.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

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


int
main()
{
	struct mmcrypt_ctx ctx;
	unsigned char k1[512 / 8];
	unsigned char k2[512 / 8];
	int rv = 0;

	mmcrypt_init(&ctx);
	rv |= mmcrypt_absorb(&ctx, "pepper", strlen("pepper"));
	rv |= mmcrypt_absorb(&ctx, "salt", strlen("salt"));
	rv |= mmcrypt_absorb(&ctx, "tag", strlen("tag"));
	rv |= mmcrypt_absorb(&ctx, "password", strlen("password"));
	if (rv != 0)
		errx(1, "mmcrypt_absorb failed");
	rv |= mmcrypt_stretch(&ctx, 1, 11, 4);
	if (rv != 0)
		errx(1, "mmcrypt_stretch failed");
	rv |= mmcrypt_squeeze(&ctx, k1, sizeof(k1));
	rv |= mmcrypt_squeeze(&ctx, k2, sizeof(k2));
	if (rv != 0)
		errx(1, "mmcrypt_squeeze failed");
	printf("k1 = %s\n", dump_hex(k1, sizeof(k1)));
	printf("k2 = %s\n", dump_hex(k2, sizeof(k2)));
	mmcrypt_destroy(&ctx);

	mmcrypt_init(&ctx);
	rv |= mmcrypt_stretch(&ctx, 1, 1, 1);
	if (rv != 0)
		errx(1, "mmcrypt_stretch failed");
	rv |= mmcrypt_squeeze(&ctx, k1, sizeof(k1));
	if (rv != 0)
		errx(1, "mmcrypt_squeeze failed");
	printf("min k1 = %s\n", dump_hex(k1, sizeof(k1)));

	return 0;
}
