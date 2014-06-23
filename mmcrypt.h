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

#ifndef MMCRYPT_H_
#define MMCRYPT_H_

#include "KeccakNISTInterface.h"
#include "KeccakDuplex.h"

struct mmcrypt_ctx {
	duplexState sm;
};

void mmcrypt_init(struct mmcrypt_ctx *ctx);

void mmcrypt_destroy(struct mmcrypt_ctx *ctx);

int mmcrypt_absorb(struct mmcrypt_ctx *ctx, const void *data, size_t datalen);

int mmcrypt_squeeze(struct mmcrypt_ctx *ctx, void *key, size_t keylen);

int mmcrypt_stretch(struct mmcrypt_ctx *ctx, uint32_t iter, uint32_t c, uint32_t s);

#endif
