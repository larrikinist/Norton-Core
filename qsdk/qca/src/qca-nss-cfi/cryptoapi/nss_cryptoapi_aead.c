/* Copyright (c) 2015-2016 The Linux Foundation. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 *
 *
 */

/**
 * nss_cryptoapi.c
 * 	Interface to communicate Native Linux crypto framework specific data
 * 	to Crypto core specific data
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/random.h>
#include <asm/scatterlist.h>
#include <linux/moduleparam.h>
#include <linux/spinlock.h>
#include <asm/cmpxchg.h>
#include <linux/delay.h>
#include <linux/crypto.h>
#include <linux/rtnetlink.h>
#include <linux/debugfs.h>

#include <crypto/ctr.h>
#include <crypto/des.h>
#include <crypto/aes.h>
#include <crypto/sha.h>
#include <crypto/hash.h>
#include <crypto/algapi.h>
#include <crypto/aead.h>
#include <crypto/authenc.h>
#include <crypto/scatterwalk.h>

#include <nss_api_if.h>
#include <nss_crypto_if.h>
#include <nss_cfi_if.h>
#include "nss_cryptoapi.h"

extern struct nss_cryptoapi gbl_ctx;

struct cryptoapi_aead_info {
	void *iv;
	struct nss_crypto_params *params;
	nss_crypto_comp_t cb_fn;
	uint16_t cip_len;
	uint16_t auth_len;
};

/*
 *
 * nss_cryptoapi_aead_init()
 * 	Cryptoapi aead init function.
 */
int nss_cryptoapi_aead_init(struct crypto_tfm *tfm)
{
	struct nss_cryptoapi_ctx *ctx = crypto_tfm_ctx(tfm);
	struct crypto_aead *sw_tfm;

	nss_cfi_assert(ctx);

	ctx->sid = NSS_CRYPTO_MAX_IDXS;
	ctx->queued = 0;
	ctx->completed = 0;
	ctx->queue_failed = 0;
	ctx->fallback_req = 0;
	atomic_set(&ctx->refcnt, 0);

	nss_cryptoapi_set_magic(ctx);

	/* Alloc fallback transform for future use */
	sw_tfm = crypto_alloc_aead(crypto_tfm_alg_name(tfm), 0, CRYPTO_ALG_ASYNC | CRYPTO_ALG_NEED_FALLBACK);
	if (IS_ERR(sw_tfm)) {
		nss_cfi_err("Unable to alloc fallback aead:%s\n", crypto_tfm_alg_name(tfm));
		return -EINVAL;
	}

	/* set this tfm reqsize same to fallback tfm */
	crypto_aead_crt(__crypto_aead_cast(tfm))->reqsize = crypto_aead_reqsize(sw_tfm);
	ctx->sw_tfm = crypto_aead_tfm(sw_tfm);

	return 0;
}

/*
 * nss_cryptoapi_aead_exit()
 * 	Cryptoapi aead exit function.
 */
void nss_cryptoapi_aead_exit(struct crypto_tfm *tfm)
{
	struct nss_cryptoapi_ctx *ctx = crypto_tfm_ctx(tfm);
	struct nss_cryptoapi *sc = &gbl_ctx;
	nss_crypto_status_t status;

	nss_cfi_assert(ctx);

	if (!atomic_dec_and_test(&ctx->refcnt)) {
		nss_cfi_err("Process done is not completed, while exit is called\n");
		nss_cfi_assert(false);
	}

	nss_cfi_assert(ctx->sw_tfm);
	crypto_free_aead(__crypto_aead_cast(ctx->sw_tfm));
	ctx->sw_tfm = NULL;

	/*
	 * When sid is NSS_CRYPTO_MAX_IDXS, it means that it didn't allocate
	 * session from qca-nss-crypto, it maybe uses software crypto.
	 */
	if (ctx->sid == NSS_CRYPTO_MAX_IDXS)
		return;

	nss_cryptoapi_debugfs_del_session(ctx);

	status = nss_crypto_session_free(sc->crypto, ctx->sid);
	if (status != NSS_CRYPTO_STATUS_OK) {
		nss_cfi_err("unable to free session: idx %d\n", ctx->sid);
	}

	nss_cryptoapi_clear_magic(ctx);
}

/*
 * nss_cryptoapi_aead_extract_key()
 * 	Populate nss_crypto_key structures for cip and auth.
 */
int nss_cryptoapi_aead_extract_key(const u8 *key, unsigned int keylen, struct nss_crypto_key *cip, struct nss_crypto_key *auth)
{
	struct rtattr *rta = (struct rtattr *)key;
	struct crypto_authenc_key_param *param;
	uint32_t enc_key_len, auth_key_len;

	if (!RTA_OK(rta, keylen)) {
		nss_cfi_err("badkey RTA attr NOT ok keylen: %d\n", keylen);
		return -EINVAL;
	}

	if (rta->rta_type != CRYPTO_AUTHENC_KEYA_PARAM) {
		nss_cfi_err("badkey rta_type != CRYPTO_AUTHENC_KEYA_PARAM, rta_type: %d\n", rta->rta_type);
		return -EINVAL;
	}

	if (RTA_PAYLOAD(rta) < sizeof(*param)) {
		nss_cfi_err("RTA_PAYLOAD < param: %d\n", sizeof(*param));
		return -EINVAL;
	}

	param = RTA_DATA(rta);

	key += RTA_ALIGN(rta->rta_len);
	keylen -= RTA_ALIGN(rta->rta_len);

	enc_key_len = be32_to_cpu(param->enckeylen);
	auth_key_len = keylen - enc_key_len;

	nss_cfi_assert(enc_key_len);
	nss_cfi_assert(auth_key_len);

	auth->key = (uint8_t *)key;
	auth->key_len = auth_key_len;

	cip->key = (uint8_t *)key + auth_key_len;
	cip->key_len = enc_key_len;

	return 0;
}

/*
 * nss_cryptoapi_sha1_aes_setkey()
 * 	Cryptoapi setkey routine for sha1/aes.
 */
int nss_cryptoapi_sha1_aes_setkey(struct crypto_aead *tfm, const u8 *key, unsigned int keylen)
{
	struct nss_cryptoapi_ctx *ctx = crypto_aead_ctx(tfm);
	struct nss_cryptoapi *sc = &gbl_ctx;
	struct nss_crypto_key cip = { .algo = NSS_CRYPTO_CIPHER_AES };
	struct nss_crypto_key auth = { .algo = NSS_CRYPTO_AUTH_SHA1_HMAC };
	uint32_t flag = CRYPTO_TFM_RES_BAD_KEY_LEN;
	int ret;
	nss_crypto_status_t status;

	/*
	 * validate magic number - init should be called before setkey
	 */
	nss_cryptoapi_verify_magic(ctx);

	if (atomic_cmpxchg(&ctx->refcnt, 0, 1)) {
		nss_cfi_err("reusing context, setkey is already called\n");
		return -EINVAL;
	}

	/*
	 * Extract and cipher and auth key
	 */
	if (nss_cryptoapi_aead_extract_key(key, keylen, &cip, &auth)) {
		nss_cfi_err("Invalid cryptoapi context\n");
		goto fail;
	}

	/*
	 * Initialize IV for this session
	 */
	get_random_bytes(ctx->ctx_iv, AES_BLOCK_SIZE);

	/*
	 * When the specified length request can't be handled by hardware,
	 * fallback to other crypto
	 */
	switch (cip.key_len) {
	case NSS_CRYPTOAPI_KEYLEN_AES128:
	case NSS_CRYPTOAPI_KEYLEN_AES256:
		/* success */
		ctx->fallback_req = false;
		break;
	case NSS_CRYPTOAPI_KEYLEN_AES192:
		/* We don't support AES192, fallback to software crypto*/
		nss_cfi_assert(ctx->sw_tfm);

		ctx->fallback_req = true;
		ctx->sid = NSS_CRYPTO_MAX_IDXS;

		/* set flag to fallback tfm */
		crypto_tfm_clear_flags(ctx->sw_tfm, CRYPTO_TFM_REQ_MASK);
		crypto_tfm_set_flags(ctx->sw_tfm, crypto_aead_get_flags(tfm) & CRYPTO_TFM_REQ_MASK);

		/* set key to the fallback tfm */
		ret = crypto_aead_setkey(__crypto_aead_cast(ctx->sw_tfm), key, keylen);
		if (ret) {
			nss_cfi_err("Setting key to software cryto failed\n");

			/*
			 * set key to the fallback tfm
			 * Set back the fallback tfm flag to the original flag one after
			 * doing setkey
			 */
			crypto_aead_set_flags(tfm, crypto_tfm_get_flags(ctx->sw_tfm));
		}
		return ret;
	default:
		nss_cfi_err("Bad Cipher key_len(%d)\n", cip.key_len);
		goto fail;
	}

	/*
	 * Validate cipher key length
	 */
	switch (auth.key_len) {
	case NSS_CRYPTO_MAX_KEYLEN_SHA1:
		/* success */
		break;
	default:
		nss_cfi_err("Bad Auth key_len(%d)\n", auth.key_len);
		goto fail;
	}

	status = nss_crypto_session_alloc(sc->crypto, &cip, &auth, &ctx->sid);
	if (status != NSS_CRYPTO_STATUS_OK) {
		nss_cfi_err("nss_crypto_session_alloc failed - status: %d\n", status);
		ctx->sid = NSS_CRYPTO_MAX_IDXS;
		flag = CRYPTO_TFM_RES_BAD_FLAGS;
		goto fail;
	}

	nss_cryptoapi_debugfs_add_session(sc, ctx);

	nss_cfi_info("session id created: %d\n", ctx->sid);

	ctx->cip_alg = NSS_CRYPTO_CIPHER_AES;
	ctx->auth_alg = NSS_CRYPTO_AUTH_SHA1_HMAC;

	return 0;

fail:
	crypto_aead_set_flags(tfm, flag);
	return -EINVAL;
}

/*
 * nss_cryptoapi_sha256_aes_setkey()
 * 	Cryptoapi setkey routine for sha256/aes.
 */
int nss_cryptoapi_sha256_aes_setkey(struct crypto_aead *tfm, const u8 *key, unsigned int keylen)
{
	struct nss_cryptoapi_ctx *ctx = crypto_aead_ctx(tfm);
	struct nss_cryptoapi *sc = &gbl_ctx;
	struct nss_crypto_key cip = { .algo = NSS_CRYPTO_CIPHER_AES };
	struct nss_crypto_key auth = { .algo = NSS_CRYPTO_AUTH_SHA256_HMAC };
	uint32_t flag = CRYPTO_TFM_RES_BAD_KEY_LEN;
	int ret;
	nss_crypto_status_t status;

	/*
	 * validate magic number - init should be called before setkey
	 */
	nss_cryptoapi_verify_magic(ctx);

	if (atomic_cmpxchg(&ctx->refcnt, 0, 1)) {
		nss_cfi_err("reusing context, setkey is already called\n");
		return -EINVAL;
	}

	/*
	 * Extract and cipher and auth key
	 */
	if (nss_cryptoapi_aead_extract_key(key, keylen, &cip, &auth)) {
		nss_cfi_err("Bad Key\n");
		goto fail;
	}

	/*
	 * Initialize IV for this session
	 */
	get_random_bytes(ctx->ctx_iv, AES_BLOCK_SIZE);

	/*
	 * When the specified length request can't be handled by hardware,
	 * fallback to other crypto
	 */
	switch (cip.key_len) {
	case NSS_CRYPTOAPI_KEYLEN_AES128:
	case NSS_CRYPTOAPI_KEYLEN_AES256:
		/* success */
		ctx->fallback_req = false;
		break;
	case NSS_CRYPTOAPI_KEYLEN_AES192:
		nss_cfi_assert(ctx->sw_tfm);

		ctx->fallback_req = true;
		ctx->sid = NSS_CRYPTO_MAX_IDXS;

		/* set flag to fallback tfm */
		crypto_tfm_clear_flags(ctx->sw_tfm, CRYPTO_TFM_REQ_MASK);
		crypto_tfm_set_flags(ctx->sw_tfm, crypto_aead_get_flags(tfm) & CRYPTO_TFM_REQ_MASK);

		/* set key to the fallback tfm */
		ret = crypto_aead_setkey(__crypto_aead_cast(ctx->sw_tfm), key, keylen);
		if (ret) {
			nss_cfi_err("Setting key to software cryto failed\n");

			/*
			 * Set back the fallback tfm flag to the original flag one after
			 * doing setkey
			 */
			crypto_aead_set_flags(tfm, crypto_tfm_get_flags(ctx->sw_tfm));
		}
		return ret;
	default:
		nss_cfi_err("Bad Cipher key_len(%d)\n", cip.key_len);
		goto fail;

	}

	/*
	 * Validate auth key length
	 */
	switch (auth.key_len) {
	case NSS_CRYPTO_MAX_KEYLEN_SHA256:
		/* success */
		break;
	default:
		nss_cfi_err("Bad Auth key_len(%d)\n", auth.key_len);
		goto fail;
	}

	status = nss_crypto_session_alloc(sc->crypto, &cip, &auth, &ctx->sid);
	if (status != NSS_CRYPTO_STATUS_OK) {
		nss_cfi_err("nss_crypto_session_alloc failed - status: %d\n", status);
		ctx->sid = NSS_CRYPTO_MAX_IDXS;
		flag = CRYPTO_TFM_RES_BAD_FLAGS;
		goto fail;
	}

	nss_cryptoapi_debugfs_add_session(sc, ctx);


	nss_cfi_info("session id created: %d\n", ctx->sid);

	ctx->cip_alg = NSS_CRYPTO_CIPHER_AES;
	ctx->auth_alg = NSS_CRYPTO_AUTH_SHA256_HMAC;

	return 0;

fail:
	crypto_aead_set_flags(tfm, flag);
	return -EINVAL;
}

/*
 * nss_cryptoapi_sha1_3des_setkey()
 * 	Cryptoapi setkey routine for sha1/3des.
 */
int nss_cryptoapi_sha1_3des_setkey(struct crypto_aead *tfm, const u8 *key, unsigned int keylen)
{
	struct nss_cryptoapi_ctx *ctx = crypto_aead_ctx(tfm);
	struct nss_cryptoapi *sc = &gbl_ctx;
	struct nss_crypto_key cip = { .algo = NSS_CRYPTO_CIPHER_DES };
	struct nss_crypto_key auth = { .algo = NSS_CRYPTO_AUTH_SHA1_HMAC };
	uint32_t flag = CRYPTO_TFM_RES_BAD_KEY_LEN;
	nss_crypto_status_t status;

	/*
	 * validate magic number - init should be called before setkey
	 */
	nss_cryptoapi_verify_magic(ctx);

	if (atomic_cmpxchg(&ctx->refcnt, 0, 1)) {
		nss_cfi_err("reusing context, setkey is already called\n");
		return -EINVAL;
	}

	/*
	 * Extract and cipher and auth key
	 */
	if (nss_cryptoapi_aead_extract_key(key, keylen, &cip, &auth)) {
		nss_cfi_err("Bad Key\n");
		goto fail;
	}

	/*
	 * Validate key length
	 */
	switch (cip.key_len) {
	case NSS_CRYPTOAPI_KEYLEN_3DES:
		/* success */
		break;
	default:
		nss_cfi_err("Bad Cipher key_len(%d)\n", cip.key_len);
		goto fail;
	}

	/*
	 * Validate cipher key length
	 */
	switch (auth.key_len) {
	case NSS_CRYPTO_MAX_KEYLEN_SHA1:
		/* success */
		break;
	default:
		nss_cfi_err("Bad Auth key_len(%d)\n", auth.key_len);
		goto fail;
	}

	status = nss_crypto_session_alloc(sc->crypto, &cip, &auth, &ctx->sid);
	if (status != NSS_CRYPTO_STATUS_OK) {
		nss_cfi_err("nss_crypto_session_alloc failed - status: %d\n", status);
		ctx->sid = NSS_CRYPTO_MAX_IDXS;
		flag = CRYPTO_TFM_RES_BAD_FLAGS;
		goto fail;
	}

	nss_cryptoapi_debugfs_add_session(sc, ctx);

	/*
	 * Initialize IV for this session
	 */
	get_random_bytes(ctx->ctx_iv, DES3_EDE_BLOCK_SIZE);

	nss_cfi_info("session id created: %d\n", ctx->sid);

	ctx->cip_alg = NSS_CRYPTO_CIPHER_DES;
	ctx->auth_alg = NSS_CRYPTO_AUTH_SHA1_HMAC;

	return 0;

fail:
	crypto_aead_set_flags(tfm, flag);
	return -EINVAL;
}

/*
 * nss_cryptoapi_sha256_3des_setkey()
 * 	Cryptoapi setkey routine for sha256/3des.
 */
int nss_cryptoapi_sha256_3des_setkey(struct crypto_aead *tfm, const u8 *key, unsigned int keylen)
{
	struct nss_cryptoapi_ctx *ctx = crypto_aead_ctx(tfm);
	struct nss_cryptoapi *sc = &gbl_ctx;
	struct nss_crypto_key cip = { .algo = NSS_CRYPTO_CIPHER_DES };
	struct nss_crypto_key auth = { .algo = NSS_CRYPTO_AUTH_SHA256_HMAC };
	uint32_t flag = CRYPTO_TFM_RES_BAD_KEY_LEN;
	nss_crypto_status_t status;

	/*
	 * validate magic number - init should be called before setkey
	 */
	nss_cryptoapi_verify_magic(ctx);

	if (atomic_cmpxchg(&ctx->refcnt, 0, 1)) {
		nss_cfi_err("reusing context, setkey is already called\n");
		return -EINVAL;
	}

	/*
	 * Extract and cipher and auth key
	 */
	if (nss_cryptoapi_aead_extract_key(key, keylen, &cip, &auth)) {
		nss_cfi_err("Bad Key\n");
		goto fail;
	}

	/*
	 * Validate key length
	 */
	switch (cip.key_len) {
	case NSS_CRYPTOAPI_KEYLEN_3DES:
		/* success */
		break;
	default:
		nss_cfi_err("Bad Cipher key_len(%d)\n", cip.key_len);
		goto fail;
	}

	/*
	 * Validate cipher key length
	 */
	switch (auth.key_len) {
	case NSS_CRYPTO_MAX_KEYLEN_SHA256:
		/* success */
		break;
	default:
		nss_cfi_err("Bad Auth key_len(%d)\n", auth.key_len);
		goto fail;
	}

	status = nss_crypto_session_alloc(sc->crypto, &cip, &auth, &ctx->sid);
	if (status != NSS_CRYPTO_STATUS_OK) {
		nss_cfi_err("nss_crypto_session_alloc failed - status: %d\n", status);
		ctx->sid = NSS_CRYPTO_MAX_IDXS;
		flag = CRYPTO_TFM_RES_BAD_FLAGS;
		goto fail;
	}

	nss_cryptoapi_debugfs_add_session(sc, ctx);

	/*
	 * Initialize IV for this session
	 */
	get_random_bytes(ctx->ctx_iv, DES3_EDE_BLOCK_SIZE);

	nss_cfi_info("session id created: %d\n", ctx->sid);

	ctx->cip_alg = NSS_CRYPTO_CIPHER_DES;
	ctx->auth_alg = NSS_CRYPTO_AUTH_SHA256_HMAC;

	return 0;

fail:
	crypto_aead_set_flags(tfm, flag);
	return -EINVAL;
}

/*
 * nss_cryptoapi_aead_setauthsize()
 * 	Cryptoapi set authsize funtion.
 */

int nss_cryptoapi_aead_setauthsize(struct crypto_aead *authenc, unsigned int authsize)
{
	/*
	 * Store the authsize.
	 */
	struct nss_cryptoapi_ctx *ctx = crypto_aead_ctx(authenc);

	ctx->authsize = authsize;
	nss_cfi_assert(ctx->sw_tfm);

	crypto_aead_setauthsize(__crypto_aead_cast(ctx->sw_tfm), authsize);
	return 0;
}

/*
 * nss_cryptoapi_aead_decrypt_done()
 * 	Cipher/Auth decrypt request completion callback function
 */
void nss_cryptoapi_aead_decrypt_done(struct nss_crypto_buf *buf)
{
	struct nss_cryptoapi_ctx *ctx;
	struct aead_request *req;
	uint8_t *data_hmac;
	uint8_t *hw_hmac;
	uint32_t hmac_sz;
	int err = 0;
	uint8_t *data;
	uint16_t tot_len;

	nss_cfi_assert(buf);

	req = (struct aead_request *)buf->cb_ctx;
	data = nss_cryptoapi_get_buf_addr(sg_virt(req->assoc), sg_virt(req->src));
	tot_len = req->assoclen + nss_cryptoapi_get_iv_sz(req) + req->cryptlen;

	/*
	 * check cryptoapi context magic number.
	 */
	ctx = crypto_tfm_ctx(req->base.tfm);
	nss_cryptoapi_verify_magic(ctx);

	hmac_sz = nss_cryptoapi_get_hmac_sz(req);
	hw_hmac = nss_crypto_get_hash_addr(buf);
	data_hmac = data + tot_len - hmac_sz;

	if (memcmp(hw_hmac, data_hmac, hmac_sz)) {
		err = -EBADMSG;
		nss_cfi_err("HMAC comparison failed\n");
	}

	nss_crypto_buf_free(gbl_ctx.crypto, buf);
	aead_request_complete(req, err);

	nss_cfi_assert(atomic_read(&ctx->refcnt));
	atomic_dec(&ctx->refcnt);
	ctx->completed++;
}

/*
 * nss_cryptoapi_aead_encrypt_done()
 * 	Cipher/Auth encrypt request completion callback function
 */
void nss_cryptoapi_aead_encrypt_done(struct nss_crypto_buf *buf)
{
	struct nss_cryptoapi_ctx *ctx;
	struct aead_request *req;
	uint8_t *hw_hmac;
	uint32_t hmac_sz;
	int err = 0;
	uint8_t *data;
	uint16_t tot_len;

	nss_cfi_assert(buf);

	req = (struct aead_request *)buf->cb_ctx;
	data = nss_cryptoapi_get_buf_addr(sg_virt(req->assoc), sg_virt(req->src));
	/* data = sg_virt(req->dst); */
	tot_len = req->assoclen + nss_cryptoapi_get_iv_sz(req) + req->cryptlen;

	/*
	 * check cryptoapi context magic number.
	 */
	ctx = crypto_tfm_ctx(req->base.tfm);
	nss_cryptoapi_verify_magic(ctx);

	hmac_sz = nss_cryptoapi_get_hmac_sz(req);
	hw_hmac = nss_crypto_get_hash_addr(buf);

	memcpy(data + tot_len, hw_hmac, hmac_sz);

	nss_crypto_buf_free(gbl_ctx.crypto, buf);
	/*
	 * Passing always pass in case of encrypt.
	 * Perhaps whenever core crypto invloke callback routine, it is always pass.
	 */
	aead_request_complete(req, err);

	nss_cfi_assert(atomic_read(&ctx->refcnt));
	atomic_dec(&ctx->refcnt);
	ctx->completed++;
}

/*
 * nss_cryptoapi_validate_addr()
 * 	Cipher/Auth operation valiate virtual addresses of sg's
 */
int nss_cryptoapi_validate_addr(struct nss_cryptoapi_addr *sg_addr)
{
	/*
	 * Currently only in-place transformation is supported.
	 */
	if (sg_addr->src != sg_addr->dst) {
		nss_cfi_err("src!=dst src: 0x%p, dst: 0x%p\n", sg_addr->src, sg_addr->dst);
		return -EINVAL;
	}

	/*
	 * Assoc should include IV, should be before cipher.
	 */
	if (sg_addr->src < sg_addr->start) {
		nss_cfi_err("Invalid cipher pointer src: 0x%p, iv: 0x%p, assoc: 0x%p\n", sg_addr->src, sg_addr->iv, sg_addr->assoc);
		return -EINVAL;
	}

	return 0;
}

/*
 * nss_cryptoapi_checknget_addr()
 * 	Cryptoapi: obtain sg to virtual address mapping.
 * 	Check for multiple sg in src, dst and assoc sg_list validate virtual address laytou
 */
int nss_cryptoapi_checknget_addr(struct aead_request *req, struct nss_cryptoapi_addr *sg_addr)
{
	uint32_t data_len;
	/*
	 * Currently only single sg is supported
	 * 	return error, if caller send multiple sg for any of src, assoc and dst.
	 */
	if (nss_cryptoapi_sg_has_frags(req->src)) {
		nss_cfi_err("Only single sg supported: src invalid\n");
		return -EINVAL;
	}

	if (nss_cryptoapi_sg_has_frags(req->dst)) {
		nss_cfi_err("Only single sg supported: dst invalid\n");
		return -EINVAL;
	}

	if (nss_cryptoapi_sg_has_frags(req->assoc)) {
		nss_cfi_err("Only single sg supported: assoc invalid\n");
		return -EINVAL;
	}

	/*
	 * If the size of data is more than 65K reject transformation
	 */
	data_len = req->cryptlen + nss_cryptoapi_get_iv_sz(req);
	data_len += req->assoclen + nss_cryptoapi_get_hmac_sz(req);
	if (data_len > NSS_CRYPTOAPI_MAX_DATA_LEN) {
		nss_cfi_err("Buffer length exceeded limit\n");
		return -EINVAL;
	}

	/*
	 * check start of buffer.
	 * Either of assoc or cipher can be start of the data
	 */
	sg_addr->src = sg_virt(req->src);
	sg_addr->dst = sg_virt(req->dst);
	sg_addr->assoc = sg_virt(req->assoc);
	sg_addr->start = nss_cryptoapi_get_buf_addr(sg_addr->assoc, sg_addr->src);

	nss_cfi_assert(sg_addr->src);
	nss_cfi_assert(sg_addr->dst);
	nss_cfi_assert(sg_addr->assoc);
	nss_cfi_assert(sg_addr->iv);
	nss_cfi_assert(sg_addr->start);

	if (nss_cryptoapi_validate_addr(sg_addr)) {
		nss_cfi_err("Invalid addresses\n");
		return -EINVAL;
	}

	return 0;
}

/*
 * nss_cryptoapi_aead_transform()
 * 	Crytoapi common routine for encryption and decryption operations.
 */
struct nss_crypto_buf *nss_cryptoapi_aead_transform(struct aead_request *req, struct cryptoapi_aead_info *info)
{
	struct nss_cryptoapi_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
	struct nss_crypto_buf *buf;
	struct nss_cryptoapi_addr sg_addr = {0};
	struct nss_cryptoapi *sc = &gbl_ctx;
	nss_crypto_status_t status;
	int tot_buf_len;
	uint16_t sha;
	uint16_t ivsize;
	uint16_t cipher_len = 0, auth_len = 0;
	uint8_t *iv_addr;

	nss_cfi_assert(ctx);

	/*
	 * Map sg to corresponding virtual addesses.
	 * validate if addresses are valid as expected and sg has single fragment.
	 */
	sg_addr.iv = info->iv;
	if (nss_cryptoapi_checknget_addr(req, &sg_addr)) {
		nss_cfi_err("Invalid address!!\n");
		return NULL;
	}

	nss_cfi_dbg("src_vaddr: 0x%p, dst_vaddr: 0x%p, assoc_vaddr: 0x%p, iv: 0x%p\n",
			sg_addr.src, sg_addr.dst, sg_addr.assoc, sg_addr.iv);

	info->params->cipher_skip = nss_cryptoapi_get_skip(sg_addr.src, sg_addr.start);
	info->params->auth_skip = nss_cryptoapi_get_skip(sg_addr.assoc, sg_addr.start);

	/*
	 * Update the crypto session data
	 */
	status = nss_crypto_session_update(sc->crypto, ctx->sid, info->params);
	if (status != NSS_CRYPTO_STATUS_OK) {
		nss_cfi_err("Invalid crypto session parameters\n");
		return NULL;
	}

	/*
	 * Allocate crypto buf
	 */
	buf = nss_crypto_buf_alloc(sc->crypto);
	if (!buf) {
		nss_cfi_err("not able to allocate crypto buffer\n");
		return NULL;
	}

	/*
	 *  set crypto buffer callback
	 */
	nss_crypto_set_cb(buf, info->cb_fn, req);
	nss_crypto_set_session_idx(buf, ctx->sid);

	sha = nss_cryptoapi_get_hmac_sz(req);
	ivsize = nss_cryptoapi_get_iv_sz(req);

	/*
	 * Get IV location and memcpy the IV
	 */
	iv_addr = nss_crypto_get_ivaddr(buf);
	memcpy(iv_addr, info->iv, ivsize);

	/*
	 * Ideally this is true only for ESP/XFRM case.
	 * Need to introduce a check here to if it's an esp packet atleast for the first packet on session.
	 */
	tot_buf_len = req->assoclen + ivsize + req->cryptlen;

	/*
	 * Fill Cipher and Auth len
	 */
	cipher_len = info->cip_len;
	auth_len = info->auth_len;


	if (cipher_len & (nss_cryptoapi_get_blocksize(req) - 1)) {
		nss_cfi_err("Invalid cipher len - Not aligned to algo blocksize\n");
		nss_crypto_buf_free(sc->crypto, buf);
		crypto_aead_set_flags(crypto_aead_reqtfm(req), CRYPTO_TFM_RES_BAD_BLOCK_LEN);
		return NULL;
	}

	/*
	 * The physical buffer data length provided to crypto will include
	 * space for authentication hash
	 */
	nss_crypto_set_data(buf, sg_addr.start, sg_addr.start, tot_buf_len + sha);
	nss_crypto_set_transform_len(buf, cipher_len, auth_len);

	nss_cfi_dbg("cipher_len: %d, iv_len: %d, auth_len: %d"
			"tot_buf_len: %d, sha: %d, cipher_skip: %d, auth_skip: %d\n",
			buf->cipher_len, ivsize, buf->auth_len,
			tot_buf_len, sha, info->params->cipher_skip, info->params->auth_skip);
	nss_cfi_dbg("before transformation\n");
	nss_cfi_dbg_data(sg_addr.start, tot_buf_len, ' ');

	return buf;
}


/*
 * nss_cryptoapi_aead_fallback()
 *	Cryptoapi fallback for aes algorithm.
 */
int nss_cryptoapi_aead_fallback(struct nss_cryptoapi_ctx *ctx, struct aead_request *req, int type)
{
	struct crypto_aead *orig_tfm = crypto_aead_reqtfm(req);
	struct aead_givcrypt_request *giv_req;
	int err;

	nss_cfi_assert(ctx->sw_tfm);

	aead_request_set_tfm(req, __crypto_aead_cast(ctx->sw_tfm));

	ctx->queued++;

	switch (type) {
	case NSS_CRYPTOAPI_ENCRYPT:
		err = crypto_aead_encrypt(req);
		break;
	case NSS_CRYPTOAPI_DECRYPT:
		err = crypto_aead_decrypt(req);
		break;
	case NSS_CRYPTOAPI_GIVENCRYPT:
		/*
		 * We need use cast back to struct aead_givcrypt_request, in the
		 * case of GIVENCRYPT, the caller has moved to givcrypt_request->areq,
		 * we need move back to the beginning of givcrypt
		 */
		giv_req = container_of(req, struct aead_givcrypt_request, areq);
		err = crypto_aead_givencrypt(giv_req);
		break;
	default:
		err = -EINVAL;
	}

	if (!err)
		ctx->completed++;

	aead_request_set_tfm(req, orig_tfm);

	return err;
}
/*
 * nss_cryptoapi_sha1_aes_encrypt()
 * 	Crytoapi encrypt for sha1/aes algorithm.
 */
int nss_cryptoapi_sha1_aes_encrypt(struct aead_request *req)
{
	struct nss_cryptoapi *sc = &gbl_ctx;
	struct nss_cryptoapi_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
	struct nss_crypto_params params = { .req_type = NSS_CRYPTO_REQ_TYPE_AUTH |
							NSS_CRYPTO_REQ_TYPE_ENCRYPT };
	struct nss_crypto_buf *buf;
	struct cryptoapi_aead_info info;

	/*
	 * check cryptoapi context magic number.
	 */
	nss_cryptoapi_verify_magic(ctx);

	if (ctx->fallback_req)
		return nss_cryptoapi_aead_fallback(ctx, req, NSS_CRYPTOAPI_ENCRYPT);

	/*
	 * Check if previous call to setkey couldn't allocate session with core crypto.
	 */
	if (ctx->sid >= NSS_CRYPTO_MAX_IDXS) {
		nss_cfi_err("Invalid session\n");
		return -EINVAL;
	}

	if (nss_crypto_get_cipher(ctx->sid) != NSS_CRYPTO_CIPHER_AES) {
		nss_cfi_err("Invalid Cipher Algo for session id: %d\n", ctx->sid);
		return -EINVAL;
	}

	if (nss_crypto_get_auth(ctx->sid) != NSS_CRYPTO_AUTH_SHA1_HMAC) {
		nss_cfi_err("Invalid Auth Algo for session id: %d\n", ctx->sid);
		return -EINVAL;
	}

	info.iv = req->iv;
	info.params = &params;
	info.cb_fn = nss_cryptoapi_aead_encrypt_done;
	info.cip_len = req->cryptlen;
	info.auth_len = req->assoclen + nss_cryptoapi_get_iv_sz(req) + req->cryptlen;

	buf = nss_cryptoapi_aead_transform(req, &info);
	if (!buf) {
		nss_cfi_err("Invalid parameters\n");
		return -EINVAL;
	}

	/*
	 *  Send the buffer to CORE layer for processing
	 */
	if (nss_crypto_transform_payload(sc->crypto, buf) !=  NSS_CRYPTO_STATUS_OK) {
		nss_cfi_info("Not enough resources with driver\n");
		nss_crypto_buf_free(sc->crypto, buf);
		ctx->queue_failed++;
		return -EINVAL;
	}

	ctx->queued++;
	atomic_inc(&ctx->refcnt);

	return -EINPROGRESS;
}

/*
 * nss_cryptoapi_sha256_aes_encrypt()
 * 	Crytoapi encrypt for sha256/aes algorithm.
 */
int nss_cryptoapi_sha256_aes_encrypt(struct aead_request *req)
{
	struct nss_cryptoapi *sc = &gbl_ctx;
	struct nss_cryptoapi_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
	struct nss_crypto_params params = { .req_type = NSS_CRYPTO_REQ_TYPE_AUTH |
							NSS_CRYPTO_REQ_TYPE_ENCRYPT };
	struct nss_crypto_buf *buf;
	struct cryptoapi_aead_info info;

	/*
	 * check cryptoapi context magic number.
	 */
	nss_cryptoapi_verify_magic(ctx);

	if (ctx->fallback_req)
		return nss_cryptoapi_aead_fallback(ctx, req, NSS_CRYPTOAPI_ENCRYPT);

	/*
	 * Check if previous call to setkey couldn't allocate session with core crypto.
	 */
	if (ctx->sid >= NSS_CRYPTO_MAX_IDXS) {
		nss_cfi_err("Invalid session\n");
		return -EINVAL;
	}

	if (nss_crypto_get_cipher(ctx->sid) != NSS_CRYPTO_CIPHER_AES) {
		nss_cfi_err("Invalid Cipher Algo for session id: %d\n", ctx->sid);
		return -EINVAL;
	}

	if (nss_crypto_get_auth(ctx->sid) != NSS_CRYPTO_AUTH_SHA256_HMAC) {
		nss_cfi_err("Invalid Auth Algo for session id: %d\n", ctx->sid);
		return -EINVAL;
	}

	info.iv = req->iv;
	info.params = &params;
	info.cb_fn = nss_cryptoapi_aead_encrypt_done;
	info.cip_len = req->cryptlen;
	info.auth_len = req->assoclen + nss_cryptoapi_get_iv_sz(req) + req->cryptlen;

	buf = nss_cryptoapi_aead_transform(req, &info);
	if (!buf) {
		nss_cfi_err("Invalid parameters\n");
		return -EINVAL;
	}

	/*
	 *  Send the buffer to CORE layer for processing
	 */
	if (nss_crypto_transform_payload(sc->crypto, buf) !=  NSS_CRYPTO_STATUS_OK) {
		nss_cfi_info("Not enough resources with driver\n");
		nss_crypto_buf_free(sc->crypto, buf);
		ctx->queue_failed++;
		return -EINVAL;
	}

	ctx->queued++;
	atomic_inc(&ctx->refcnt);

	return -EINPROGRESS;
}


/*
 * nss_cryptoapi_sha1_3des_encrypt()
 * 	Crytoapi encrypt for sha1/3des algorithm.
 */
int nss_cryptoapi_sha1_3des_encrypt(struct aead_request *req)
{
	struct nss_cryptoapi *sc = &gbl_ctx;
	struct nss_cryptoapi_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
	struct nss_crypto_params params = { .req_type = NSS_CRYPTO_REQ_TYPE_AUTH |
							NSS_CRYPTO_REQ_TYPE_ENCRYPT };
	struct nss_crypto_buf *buf;
	struct cryptoapi_aead_info info;

	/*
	 * check cryptoapi context magic number.
	 */
	nss_cryptoapi_verify_magic(ctx);

	/*
	 * Check if previous call to setkey couldn't allocate session with core crypto.
	 */
	if (ctx->sid >= NSS_CRYPTO_MAX_IDXS) {
		nss_cfi_err("Invalid session\n");
		return -EINVAL;
	}

	if (nss_crypto_get_cipher(ctx->sid) != NSS_CRYPTO_CIPHER_DES) {
		nss_cfi_err("Invalid Cipher Algo for session id: %d\n", ctx->sid);
		return -EINVAL;
	}

	if (nss_crypto_get_auth(ctx->sid) != NSS_CRYPTO_AUTH_SHA1_HMAC) {
		nss_cfi_err("Invalid Auth Algo for session id: %d\n", ctx->sid);
		return -EINVAL;
	}

	info.iv = req->iv;
	info.params = &params;
	info.cb_fn = nss_cryptoapi_aead_encrypt_done;
	info.cip_len = req->cryptlen;
	info.auth_len = req->assoclen + nss_cryptoapi_get_iv_sz(req) + req->cryptlen;

	buf = nss_cryptoapi_aead_transform(req, &info);
	if (!buf) {
		nss_cfi_err("Invalid parameters\n");
		return -EINVAL;
	}

	/*
	 *  Send the buffer to CORE layer for processing
	 */
	if (nss_crypto_transform_payload(sc->crypto, buf) !=  NSS_CRYPTO_STATUS_OK) {
		nss_cfi_info("Not enough resources with driver\n");
		nss_crypto_buf_free(sc->crypto, buf);
		ctx->queue_failed++;
		return -EINVAL;
	}

	ctx->queued++;
	atomic_inc(&ctx->refcnt);

	return -EINPROGRESS;
}

/*
 * nss_cryptoapi_sha256_3des_encrypt()
 * 	Crytoapi encrypt for sha256/3des algorithm.
 */
int nss_cryptoapi_sha256_3des_encrypt(struct aead_request *req)
{
	struct nss_cryptoapi *sc = &gbl_ctx;
	struct nss_cryptoapi_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
	struct nss_crypto_params params = { .req_type = NSS_CRYPTO_REQ_TYPE_AUTH |
							NSS_CRYPTO_REQ_TYPE_ENCRYPT };
	struct nss_crypto_buf *buf;
	struct cryptoapi_aead_info info;

	/*
	 * check cryptoapi context magic number.
	 */
	nss_cryptoapi_verify_magic(ctx);

	/*
	 * Check if previous call to setkey couldn't allocate session with core crypto.
	 */
	if (ctx->sid >= NSS_CRYPTO_MAX_IDXS) {
		nss_cfi_err("Invalid session\n");
		return -EINVAL;
	}

	if (nss_crypto_get_cipher(ctx->sid) != NSS_CRYPTO_CIPHER_DES) {
		nss_cfi_err("Invalid Cipher Algo for session id: %d\n", ctx->sid);
		return -EINVAL;
	}

	if (nss_crypto_get_auth(ctx->sid) != NSS_CRYPTO_AUTH_SHA256_HMAC) {
		nss_cfi_err("Invalid Auth Algo for session id: %d\n", ctx->sid);
		return -EINVAL;
	}

	info.iv = req->iv;
	info.params = &params;
	info.cb_fn = nss_cryptoapi_aead_encrypt_done;
	info.cip_len = req->cryptlen;
	info.auth_len = req->assoclen + nss_cryptoapi_get_iv_sz(req) + req->cryptlen;

	buf = nss_cryptoapi_aead_transform(req, &info);
	if (!buf) {
		nss_cfi_err("Invalid parameters\n");
		return -EINVAL;
	}

	/*
	 *  Send the buffer to CORE layer for processing
	 */
	if (nss_crypto_transform_payload(sc->crypto, buf) !=  NSS_CRYPTO_STATUS_OK) {
		nss_cfi_info("Not enough resources with driver\n");
		nss_crypto_buf_free(sc->crypto, buf);
		ctx->queue_failed++;
		return -EINVAL;
	}

	ctx->queued++;
	atomic_inc(&ctx->refcnt);

	return -EINPROGRESS;
}

/*
 * nss_cryptoapi_sha1_aes_decrypt()
 * 	Crytoapi decrypt for sha1/aes algorithm.
 */
int nss_cryptoapi_sha1_aes_decrypt(struct aead_request *req)
{
	struct nss_cryptoapi *sc = &gbl_ctx;
	struct nss_cryptoapi_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
	struct nss_crypto_params params = { .req_type = NSS_CRYPTO_REQ_TYPE_AUTH |
							NSS_CRYPTO_REQ_TYPE_DECRYPT };
	struct nss_crypto_buf *buf;
	struct cryptoapi_aead_info info;

	/*
	 * check cryptoapi context magic number.
	 */
	nss_cryptoapi_verify_magic(ctx);

	if (ctx->fallback_req)
		return nss_cryptoapi_aead_fallback(ctx, req, NSS_CRYPTOAPI_DECRYPT);

	/*
	 * Check if previous call to setkey couldn't allocate session with core crypto.
	 */
	if (ctx->sid >= NSS_CRYPTO_MAX_IDXS) {
		nss_cfi_err("Invalid session\n");
		return -EINVAL;
	}

	if (nss_crypto_get_cipher(ctx->sid) != NSS_CRYPTO_CIPHER_AES) {
		nss_cfi_err("Invalid Cipher Algo for session id: %d\n", ctx->sid);
		return -EINVAL;
	}

	if (nss_crypto_get_auth(ctx->sid) != NSS_CRYPTO_AUTH_SHA1_HMAC) {
		nss_cfi_err("Invalid Auth Algo for session id: %d\n", ctx->sid);
		return -EINVAL;
	}

	/*
	 * In case of decrypt operation, ipsec include hmac size in req->cryptlen
	 * skip encryption and authentication on hmac trasmitted with data.
	 * TODO: fix this in future, pass relevant details from caller.
	 */
	info.iv = req->iv;
	info.params = &params;
	info.cb_fn = nss_cryptoapi_aead_decrypt_done;
	info.cip_len = req->cryptlen - nss_cryptoapi_get_hmac_sz(req);
	info.auth_len = req->assoclen + nss_cryptoapi_get_iv_sz(req) + req->cryptlen - nss_cryptoapi_get_hmac_sz(req);

	buf = nss_cryptoapi_aead_transform(req, &info);
	if (!buf) {
		nss_cfi_err("Invalid parameters\n");
		return -EINVAL;
	}

	/*
	 *  Send the buffer to CORE layer for processing
	 */
	if (nss_crypto_transform_payload(sc->crypto, buf) !=  NSS_CRYPTO_STATUS_OK) {
		nss_cfi_info("Not enough resources with driver\n");
		nss_crypto_buf_free(sc->crypto, buf);
		ctx->queue_failed++;
		return -EINVAL;
	}

	ctx->queued++;
	atomic_inc(&ctx->refcnt);

	return -EINPROGRESS;
}

/*
 * nss_cryptoapi_sha256_aes_decrypt()
 * 	Crytoapi decrypt for sha256/aes algorithm.
 */
int nss_cryptoapi_sha256_aes_decrypt(struct aead_request *req)
{
	struct nss_cryptoapi *sc = &gbl_ctx;
	struct nss_cryptoapi_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
	struct nss_crypto_params params = { .req_type = NSS_CRYPTO_REQ_TYPE_AUTH |
							NSS_CRYPTO_REQ_TYPE_DECRYPT };
	struct nss_crypto_buf *buf;
	struct cryptoapi_aead_info info;

	/*
	 * check cryptoapi context magic number.
	 */
	nss_cryptoapi_verify_magic(ctx);

	if (ctx->fallback_req)
		return nss_cryptoapi_aead_fallback(ctx, req, NSS_CRYPTOAPI_DECRYPT);

	/*
	 * Check if previous call to setkey couldn't allocate session with core crypto.
	 */
	if (ctx->sid >= NSS_CRYPTO_MAX_IDXS) {
		nss_cfi_err("Invalid session\n");
		return -EINVAL;
	}

	if (nss_crypto_get_cipher(ctx->sid) != NSS_CRYPTO_CIPHER_AES) {
		nss_cfi_err("Invalid Cipher Algo for session id: %d\n", ctx->sid);
		return -EINVAL;
	}

	if (nss_crypto_get_auth(ctx->sid) != NSS_CRYPTO_AUTH_SHA256_HMAC) {
		nss_cfi_err("Invalid Auth Algo for session id: %d\n", ctx->sid);
		return -EINVAL;
	}

	/*
	 * In case of decrypt operation, ipsec include hmac size in req->cryptlen
	 * skip encryption and authentication on hmac trasmitted with data.
	 * TODO: fix this in future, pass relevant details from caller.
	 */
	info.iv = req->iv;
	info.params = &params;
	info.cb_fn = nss_cryptoapi_aead_decrypt_done;
	info.cip_len = req->cryptlen - nss_cryptoapi_get_hmac_sz(req);
	info.auth_len = req->assoclen + nss_cryptoapi_get_iv_sz(req) + req->cryptlen - nss_cryptoapi_get_hmac_sz(req);

	buf = nss_cryptoapi_aead_transform(req, &info);
	if (!buf) {
		nss_cfi_err("Invalid parameters\n");
		return -EINVAL;
	}

	/*
	 *  Send the buffer to CORE layer for processing
	 */
	if (nss_crypto_transform_payload(sc->crypto, buf) !=  NSS_CRYPTO_STATUS_OK) {
		nss_cfi_info("Not enough resources with driver\n");
		nss_crypto_buf_free(sc->crypto, buf);
		ctx->queue_failed++;
		return -EINVAL;
	}

	ctx->queued++;
	atomic_inc(&ctx->refcnt);

	return -EINPROGRESS;
}

/*
 * nss_cryptoapi_sha1_3des_decrypt()
 * 	Crytoapi decrypt for sha1/3des algorithm.
 */
int nss_cryptoapi_sha1_3des_decrypt(struct aead_request *req)
{
	struct nss_cryptoapi *sc = &gbl_ctx;
	struct nss_cryptoapi_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
	struct nss_crypto_params params = { .req_type = NSS_CRYPTO_REQ_TYPE_AUTH |
							NSS_CRYPTO_REQ_TYPE_DECRYPT };
	struct nss_crypto_buf *buf;
	struct cryptoapi_aead_info info;

	/*
	 * check cryptoapi context magic number.
	 */
	nss_cryptoapi_verify_magic(ctx);

	/*
	 * Check if previous call to setkey couldn't allocate session with core crypto.
	 */
	if (ctx->sid >= NSS_CRYPTO_MAX_IDXS) {
		nss_cfi_err("Invalid session\n");
		return -EINVAL;
	}

	if (nss_crypto_get_cipher(ctx->sid) != NSS_CRYPTO_CIPHER_DES) {
		nss_cfi_err("Invalid Cipher Algo for session id: %d\n", ctx->sid);
		return -EINVAL;
	}

	if (nss_crypto_get_auth(ctx->sid) != NSS_CRYPTO_AUTH_SHA1_HMAC) {
		nss_cfi_err("Invalid Auth Algo for session id: %d\n", ctx->sid);
		return -EINVAL;
	}

	/*
	 * In case of decrypt operation, ipsec include hmac size in req->cryptlen
	 * skip encryption and authentication on hmac trasmitted with data.
	 * TODO: fix this in future, pass relevant details from caller.
	 */
	info.iv = req->iv;
	info.params = &params;
	info.cb_fn = nss_cryptoapi_aead_decrypt_done;
	info.cip_len = req->cryptlen - nss_cryptoapi_get_hmac_sz(req);
	info.auth_len = req->assoclen + nss_cryptoapi_get_iv_sz(req) + req->cryptlen - nss_cryptoapi_get_hmac_sz(req);

	buf = nss_cryptoapi_aead_transform(req, &info);
	if (!buf) {
		nss_cfi_err("Invalid parameters\n");
		return -EINVAL;
	}

	/*
	 *  Send the buffer to CORE layer for processing
	 */
	if (nss_crypto_transform_payload(sc->crypto, buf) !=  NSS_CRYPTO_STATUS_OK) {
		nss_cfi_info("Not enough resources with driver\n");
		nss_crypto_buf_free(sc->crypto, buf);
		ctx->queue_failed++;
		return -EINVAL;
	}

	ctx->queued++;
	atomic_inc(&ctx->refcnt);

	return -EINPROGRESS;
}

/*
 * nss_cryptoapi_sha256_3des_decrypt()
 * 	Crytoapi decrypt for sha256/3des algorithm.
 */
int nss_cryptoapi_sha256_3des_decrypt(struct aead_request *req)
{
	struct nss_cryptoapi *sc = &gbl_ctx;
	struct nss_cryptoapi_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
	struct nss_crypto_params params = { .req_type = NSS_CRYPTO_REQ_TYPE_AUTH |
							NSS_CRYPTO_REQ_TYPE_DECRYPT };
	struct nss_crypto_buf *buf;
	struct cryptoapi_aead_info info;

	/*
	 * check cryptoapi context magic number.
	 */
	nss_cryptoapi_verify_magic(ctx);

	/*
	 * Check if previous call to setkey couldn't allocate session with core crypto.
	 */
	if (ctx->sid >= NSS_CRYPTO_MAX_IDXS) {
		nss_cfi_err("Invalid session\n");
		return -EINVAL;
	}

	if (nss_crypto_get_cipher(ctx->sid) != NSS_CRYPTO_CIPHER_DES) {
		nss_cfi_err("Invalid Cipher Algo for session id: %d\n", ctx->sid);
		return -EINVAL;
	}

	if (nss_crypto_get_auth(ctx->sid) != NSS_CRYPTO_AUTH_SHA256_HMAC) {
		nss_cfi_err("Invalid Auth Algo for session id: %d\n", ctx->sid);
		return -EINVAL;
	}

	/*
	 * In case of decrypt operation, ipsec include hmac size in req->cryptlen
	 * skip encryption and authentication on hmac trasmitted with data.
	 * TODO: fix this in future, pass relevant details from caller.
	 */
	info.iv = req->iv;
	info.params = &params;
	info.cb_fn = nss_cryptoapi_aead_decrypt_done;
	info.cip_len = req->cryptlen - nss_cryptoapi_get_hmac_sz(req);
	info.auth_len = req->assoclen + nss_cryptoapi_get_iv_sz(req) + req->cryptlen - nss_cryptoapi_get_hmac_sz(req);

	buf = nss_cryptoapi_aead_transform(req, &info);
	if (!buf) {
		nss_cfi_err("Invalid parameters\n");
		return -EINVAL;
	}

	/*
	 *  Send the buffer to CORE layer for processing
	 */
	if (nss_crypto_transform_payload(sc->crypto, buf) !=  NSS_CRYPTO_STATUS_OK) {
		nss_cfi_info("Not enough resources with driver\n");
		nss_crypto_buf_free(sc->crypto, buf);
		ctx->queue_failed++;
		return -EINVAL;
	}

	ctx->queued++;
	atomic_inc(&ctx->refcnt);

	return -EINPROGRESS;
}

/*
 * nss_cryptoapi_sha1_aes_geniv_encrypt()
 * 	Crytoapi generate IV encrypt for sha1/aes algorithm.
 */
int nss_cryptoapi_sha1_aes_geniv_encrypt(struct aead_givcrypt_request *req)
{
	struct nss_cryptoapi *sc = &gbl_ctx;
	struct nss_cryptoapi_ctx *ctx = crypto_tfm_ctx(req->areq.base.tfm);
	struct nss_crypto_params params = { .req_type = NSS_CRYPTO_REQ_TYPE_AUTH |
							NSS_CRYPTO_REQ_TYPE_ENCRYPT };
	struct nss_crypto_buf *buf;
	struct cryptoapi_aead_info info;


	/*
	 * check cryptoapi context magic number.
	 */
	nss_cryptoapi_verify_magic(ctx);

	if (ctx->fallback_req) {
		/*
		 * fill in iv.
		 */
		memcpy(req->giv, ctx->ctx_iv, AES_BLOCK_SIZE);
		*(__be64 *)req->giv ^= cpu_to_be64(req->seq);

		return nss_cryptoapi_aead_fallback(ctx, &req->areq, NSS_CRYPTOAPI_GIVENCRYPT);
	}

	/*
	 * Check if previous call to setkey couldn't allocate session with core crypto.
	 */
	if (ctx->sid >= NSS_CRYPTO_MAX_IDXS) {
		nss_cfi_err("Invalid session\n");
		return -EINVAL;
	}

	if (nss_crypto_get_cipher(ctx->sid) != NSS_CRYPTO_CIPHER_AES) {
		nss_cfi_err("Invalid Cipher Algo for session id: %d\n", ctx->sid);
		return -EINVAL;
	}

	if (nss_crypto_get_auth(ctx->sid) != NSS_CRYPTO_AUTH_SHA1_HMAC) {
		nss_cfi_err("Invalid Auth Algo for session id: %d\n", ctx->sid);
		return -EINVAL;
	}

	/*
	 * fill in iv.
	 */
	memcpy(req->giv, ctx->ctx_iv, AES_BLOCK_SIZE);
	*(__be64 *)req->giv ^= cpu_to_be64(req->seq);

	info.iv = req->giv;
	info.params = &params;
	info.cb_fn = nss_cryptoapi_aead_encrypt_done;
	info.cip_len = req->areq.cryptlen;
	info.auth_len = req->areq.assoclen + nss_cryptoapi_get_iv_sz(&req->areq) + req->areq.cryptlen;

	buf = nss_cryptoapi_aead_transform(&req->areq, &info);
	if (!buf) {
		nss_cfi_err("Invalid parameters\n");
		return -EINVAL;
	}

	/*
	 *  Send the buffer to CORE layer for processing
	 */
	if (nss_crypto_transform_payload(sc->crypto, buf) !=  NSS_CRYPTO_STATUS_OK) {
		nss_cfi_info("Not enough resources with driver\n");
		nss_crypto_buf_free(sc->crypto, buf);
		ctx->queue_failed++;
		return -EINVAL;
	}

	ctx->queued++;
	atomic_inc(&ctx->refcnt);

	return -EINPROGRESS;
}

/*
 * nss_cryptoapi_sha256_aes_geniv_encrypt()
 * 	Crytoapi generate IV encrypt for sha256/aes algorithm.
 */
int nss_cryptoapi_sha256_aes_geniv_encrypt(struct aead_givcrypt_request *req)
{
	struct nss_cryptoapi *sc = &gbl_ctx;
	struct nss_cryptoapi_ctx *ctx = crypto_tfm_ctx(req->areq.base.tfm);
	struct nss_crypto_params params = { .req_type = NSS_CRYPTO_REQ_TYPE_AUTH |
							NSS_CRYPTO_REQ_TYPE_ENCRYPT };
	struct nss_crypto_buf *buf;
	struct cryptoapi_aead_info info;

	/*
	 * check cryptoapi context magic number.
	 */
	nss_cryptoapi_verify_magic(ctx);


	if (ctx->fallback_req) {
		/*
		 * fill in iv.
		 */
		memcpy(req->giv, ctx->ctx_iv, AES_BLOCK_SIZE);
		*(__be64 *)req->giv ^= cpu_to_be64(req->seq);

		return nss_cryptoapi_aead_fallback(ctx, &req->areq, NSS_CRYPTOAPI_GIVENCRYPT);
	}

	/*
	 * Check if previous call to setkey couldn't allocate session with core crypto.
	 */
	if (ctx->sid >= NSS_CRYPTO_MAX_IDXS) {
		nss_cfi_err("Invalid session\n");
		return -EINVAL;
	}

	if (nss_crypto_get_cipher(ctx->sid) != NSS_CRYPTO_CIPHER_AES) {
		nss_cfi_err("Invalid Cipher Algo for session id: %d\n", ctx->sid);
		return -EINVAL;
	}

	if (nss_crypto_get_auth(ctx->sid) != NSS_CRYPTO_AUTH_SHA256_HMAC) {
		nss_cfi_err("Invalid Auth Algo for session id: %d\n", ctx->sid);
		return -EINVAL;
	}

	/*
	 * fill in iv.
	 */
	memcpy(req->giv, ctx->ctx_iv, AES_BLOCK_SIZE);
	*(__be64 *)req->giv ^= cpu_to_be64(req->seq);

	info.iv = req->giv;
	info.params = &params;
	info.cb_fn = nss_cryptoapi_aead_encrypt_done;
	info.cip_len = req->areq.cryptlen;
	info.auth_len = req->areq.assoclen + nss_cryptoapi_get_iv_sz(&req->areq) + req->areq.cryptlen;

	buf = nss_cryptoapi_aead_transform(&req->areq, &info);
	if (!buf) {
		nss_cfi_err("Invalid parameters\n");
		return -EINVAL;
	}

	/*
	 *  Send the buffer to CORE layer for processing
	 */
	if (nss_crypto_transform_payload(sc->crypto, buf) !=  NSS_CRYPTO_STATUS_OK) {
		nss_cfi_info("Not enough resources with driver\n");
		nss_crypto_buf_free(sc->crypto, buf);
		ctx->queue_failed++;
		return -EINVAL;
	}

	ctx->queued++;
	atomic_inc(&ctx->refcnt);

	return -EINPROGRESS;
}

/*
 * nss_cryptoapi_sha1_3des_geniv_encrypt()
 * 	Crytoapi generate IV encrypt for sha1/3des algorithm.
 */
int nss_cryptoapi_sha1_3des_geniv_encrypt(struct aead_givcrypt_request *req)
{
	struct nss_cryptoapi *sc = &gbl_ctx;
	struct nss_cryptoapi_ctx *ctx = crypto_tfm_ctx(req->areq.base.tfm);
	struct nss_crypto_params params = { .req_type = NSS_CRYPTO_REQ_TYPE_AUTH |
							NSS_CRYPTO_REQ_TYPE_ENCRYPT };
	struct nss_crypto_buf *buf;
	struct cryptoapi_aead_info info;

	/*
	 * check cryptoapi context magic number.
	 */
	nss_cryptoapi_verify_magic(ctx);

	/*
	 * Check if previous call to setkey couldn't allocate session with core crypto.
	 */
	if (ctx->sid >= NSS_CRYPTO_MAX_IDXS) {
		nss_cfi_err("Invalid session\n");
		return -EINVAL;
	}

	if (nss_crypto_get_cipher(ctx->sid) != NSS_CRYPTO_CIPHER_DES) {
		nss_cfi_err("Invalid Cipher Algo for session id: %d\n", ctx->sid);
		return -EINVAL;
	}

	if (nss_crypto_get_auth(ctx->sid) != NSS_CRYPTO_AUTH_SHA1_HMAC) {
		nss_cfi_err("Invalid Auth Algo for session id: %d\n", ctx->sid);
		return -EINVAL;
	}

	/*
	 * fill in iv.
	 */
	memcpy(req->giv, ctx->ctx_iv, DES3_EDE_BLOCK_SIZE);
	*(__be64 *)req->giv ^= cpu_to_be64(req->seq);

	info.iv = req->giv;
	info.params = &params;
	info.cb_fn = nss_cryptoapi_aead_encrypt_done;
	info.cip_len = req->areq.cryptlen;
	info.auth_len = req->areq.assoclen + nss_cryptoapi_get_iv_sz(&req->areq) + req->areq.cryptlen;

	buf = nss_cryptoapi_aead_transform(&req->areq, &info);
	if (!buf) {
		nss_cfi_err("Invalid parameters\n");
		return -EINVAL;
	}

	/*
	 *  Send the buffer to CORE layer for processing
	 */
	if (nss_crypto_transform_payload(sc->crypto, buf) !=  NSS_CRYPTO_STATUS_OK) {
		nss_cfi_info("Not enough resources with driver\n");
		nss_crypto_buf_free(sc->crypto, buf);
		ctx->queue_failed++;
		return -EINVAL;
	}

	ctx->queued++;
	atomic_inc(&ctx->refcnt);

	return -EINPROGRESS;
}

/*
 * nss_cryptoapi_sha256_3des_geniv_encrypt()
 * 	Crytoapi generate IV encrypt for sha256/3des algorithm.
 */
int nss_cryptoapi_sha256_3des_geniv_encrypt(struct aead_givcrypt_request *req)
{
	struct nss_cryptoapi *sc = &gbl_ctx;
	struct nss_cryptoapi_ctx *ctx = crypto_tfm_ctx(req->areq.base.tfm);
	struct nss_crypto_params params = { .req_type = NSS_CRYPTO_REQ_TYPE_AUTH |
							NSS_CRYPTO_REQ_TYPE_ENCRYPT };
	struct nss_crypto_buf *buf;
	struct cryptoapi_aead_info info;

	/*
	 * check cryptoapi context magic number.
	 */
	nss_cryptoapi_verify_magic(ctx);

	/*
	 * Check if previous call to setkey couldn't allocate session with core crypto.
	 */
	if (ctx->sid >= NSS_CRYPTO_MAX_IDXS) {
		nss_cfi_err("Invalid session\n");
		return -EINVAL;
	}

	if (nss_crypto_get_cipher(ctx->sid) != NSS_CRYPTO_CIPHER_DES) {
		nss_cfi_err("Invalid Cipher Algo for session id: %d\n", ctx->sid);
		return -EINVAL;
	}

	if (nss_crypto_get_auth(ctx->sid) != NSS_CRYPTO_AUTH_SHA256_HMAC) {
		nss_cfi_err("Invalid Auth Algo for session id: %d\n", ctx->sid);
		return -EINVAL;
	}

	/*
	 * fill in iv.
	 */
	memcpy(req->giv, ctx->ctx_iv, DES3_EDE_BLOCK_SIZE);
	*(__be64 *)req->giv ^= cpu_to_be64(req->seq);

	info.iv = req->giv;
	info.params = &params;
	info.cb_fn = nss_cryptoapi_aead_encrypt_done;
	info.cip_len = req->areq.cryptlen;
	info.auth_len = req->areq.assoclen + nss_cryptoapi_get_iv_sz(&req->areq) + req->areq.cryptlen;

	buf = nss_cryptoapi_aead_transform(&req->areq, &info);
	if (!buf) {
		nss_cfi_err("Invalid parameters\n");
		return -EINVAL;
	}

	/*
	 *  Send the buffer to CORE layer for processing
	 */
	if (nss_crypto_transform_payload(sc->crypto, buf) !=  NSS_CRYPTO_STATUS_OK) {
		nss_cfi_info("Not enough resources with driver\n");
		nss_crypto_buf_free(sc->crypto, buf);
		ctx->queue_failed++;
		return -EINVAL;
	}

	ctx->queued++;
	atomic_inc(&ctx->refcnt);

	return -EINPROGRESS;
}

