/* SPDX-License-Identifier: GPL-2.0 */
/******************************************************************************
 *
 * Copyright(c) 2020, Seekwave Corporation. All right reserved.
 *
 *****************************************************************************/
#ifndef __SKW_IW_H__
#define __SKW_IW_H__

#define SKW_MAX_TLV_BUFF_LEN          1024

#define SKW_KEEPACTIVE_RULE_MAX            5
struct skw_keep_active_rule {
	u32 keep_interval;
	u16 is_chksumed;
	u8 payload[64];
	u8 payload_len;
} __packed;

struct skw_keep_active_setup {
	u32 en_bitmap;
	struct skw_keep_active_rule rules[SKW_KEEPACTIVE_RULE_MAX];
} __packed;

struct skw_keep_active_param {
	u8 rule_num;
	struct skw_keep_active_rule rules[0];
} __packed;

typedef int (*skw_at_handler)(struct skw_core *skw, void *param,
			char *args, char *resp, int resp_len);

struct skw_at_cmd {
	char *name;
	skw_at_handler handler;
	char *help_info;
};

typedef int (*skw_iwpriv_handler)(struct skw_iface *iface, void *param,
			char *args, char *resp, int resp_len);

struct skw_iwpriv_cmd {
	char *name;
	skw_iwpriv_handler handler;
	char *help_info;
};

struct skw_iw_priv_mode {
	char *name;
	enum SKW_MODE_INFO mode;
};

const void *skw_iw_handlers(void);
#endif
