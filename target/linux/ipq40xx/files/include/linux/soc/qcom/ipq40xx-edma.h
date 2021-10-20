/* SPDX-License-Identifier: GPL-2.0 OR ISC */
/*
 * This file is based on the "ess_edma.h" header file from the Qualcomm
 * Atheros SDK (QSDK). The reference file contained the following
 * permission and copyright notice:
 *
 * Copyright (c) 2014 - 2016, The Linux Foundation. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all copies.
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef IPQ40XX_EDMA_H
#define IPQ40XX_EDMA_H

/* Receive Return Descriptor */
struct edma_rrd {
	u16 rrd0;
	u16 rrd1;
	u16 rrd2;
	u16 rrd3;
	u16 rrd4;
	u16 rrd5;
	u16 rrd6;
	u16 rrd7;
} __packed;

#define EDMA_RRD_SIZE			sizeof(struct edma_rrd)

#define EDMA_RRD1_PORT_ID_MASK		GENMASK(14, 12)

#endif /* IPQ40XX_EDMA_H */
