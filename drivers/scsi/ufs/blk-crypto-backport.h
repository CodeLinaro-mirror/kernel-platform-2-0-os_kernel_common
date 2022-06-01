#ifndef _BLK_CRYPTO_BACKPORT_H_
#define _BLK_CRYPTO_BACKPORT_H_

/*
 * Allow the v5.16 crypto API to be used in kernel v5.15. See also commit
 * cb77cb5abe1f ("blk-crypto: rename blk_keyslot_manager to
 * blk_crypto_profile"; v5.16).
 */

/* Structure names */
#define blk_crypto_profile blk_keyslot_manager
#define modes_supported crypto_modes_supported

/* Structure member names */
#define ll_ops ksm_ll_ops
#define blk_crypto_ll_ops blk_ksm_ll_ops

/* Function names */
#define blk_crypto_register blk_ksm_register
#define blk_crypto_profile_init blk_ksm_init
#define devm_blk_crypto_profile_init devm_blk_ksm_init
#define blk_crypto_keyslot_index blk_ksm_get_slot_idx
#define blk_crypto_put_keyslot blk_ksm_put_slot
#define __blk_crypto_evict_key blk_ksm_evict_key
#define blk_crypto_reprogram_all_keys blk_ksm_reprogram_all_keys
#define blk_crypto_profile_destroy blk_ksm_destroy
#define blk_crypto_intersect_capabilities blk_ksm_intersect_modes
#define blk_crypto_has_capabilities blk_ksm_is_superset
#define blk_crypto_update_capabilities blk_ksm_update_capabilities

#endif /* _BLK_CRYPTO_BACKPORT_H_ */
