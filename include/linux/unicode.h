/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_UNICODE_H
#define _LINUX_UNICODE_H

#include <linux/init.h>
#include <linux/dcache.h>
#include <linux/fscrypt.h>
#include <linux/fs.h>

struct unicode_map {
	const char *charset;
	int version;
};

int utf8_validate(const struct unicode_map *um, const struct qstr *str);

int utf8_strncmp(const struct unicode_map *um,
		 const struct qstr *s1, const struct qstr *s2);

int utf8_strncasecmp(const struct unicode_map *um,
		 const struct qstr *s1, const struct qstr *s2);
int utf8_strncasecmp_folded(const struct unicode_map *um,
			    const struct qstr *cf,
			    const struct qstr *s1);

int utf8_normalize(const struct unicode_map *um, const struct qstr *str,
		   unsigned char *dest, size_t dlen);

int utf8_casefold(const struct unicode_map *um, const struct qstr *str,
		  unsigned char *dest, size_t dlen);

struct unicode_map *utf8_load(const char *version);
void utf8_unload(struct unicode_map *um);

#ifdef CONFIG_UNICODE
static inline bool needs_casefold(const struct inode *dir)
{
	return IS_CASEFOLDED(dir) && dir->i_sb->s_encoding &&
			(!IS_ENCRYPTED(dir) || fscrypt_has_encryption_key(dir));
}
#else
static inline bool needs_casefold(const struct inode *dir)
{
	return 0;
}
#endif
#endif /* _LINUX_UNICODE_H */
