/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef DSA_IPQ40XX_H
#define DSA_IPQ40XX_H

struct ipq40xx_dsa_tag_data {
	u8 from_cpu;
	u8 dp;
};

/* defitions for in-band DSA tag */
#define IPQ40XX_DSA_TAG_PROTO	ETH_P_DSA_8021Q

#define IPQ40XX_DSA_DP_MASK	GENMASK(6, 0)
#define IPQ40XX_DSA_FROM_CPU	BIT(7)

#endif /* DSA_IPQ40XX_H */
