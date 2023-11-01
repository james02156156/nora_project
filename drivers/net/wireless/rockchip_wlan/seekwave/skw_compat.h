/* SPDX-License-Identifier: GPL-2.0 */
/******************************************************************************
 *
 * Copyright(c) 2020, Seekwave Corporation. All right reserved.
 *
 *****************************************************************************/
#ifndef __SKW_COMPAT_H__
#define __SKW_COMPAT_H__

#include <linux/version.h>
#include <linux/skbuff.h>
#include <net/cfg80211.h>
#include <linux/rtc.h>

/* EID block */
#define SKW_WLAN_EID_EXT_HE_CAPABILITY                            35
#define SKW_WLAN_EID_MULTI_BSSID_IDX                              85
#define SKW_WLAN_EID_EXTENSION                                    255
#define SKW_WLAN_EID_FRAGMENT                                     242

/* compat for ieee80211 */
#define SKW_HE_MAC_CAP0_HTC_HE                                    0x01
#define SKW_HE_MAC_CAP1_TF_MAC_PAD_DUR_16US                       0x08
#define SKW_HE_MAC_CAP1_MULTI_TID_AGG_RX_QOS_8                    0x70

#define SKW_HE_MAC_CAP2_BSR                                       0x08
#define SKW_HE_MAC_CAP2_MU_CASCADING                              0x40
#define SKW_HE_MAC_CAP2_ACK_EN                                    0x80

#define SKW_HE_MAC_CAP3_GRP_ADDR_MULTI_STA_BA_DL_MU               0x01
#define SKW_HE_MAC_CAP3_OMI_CONTROL                               0x02
#define SKW_HE_MAC_CAP3_MAX_AMPDU_LEN_EXP_VHT_2                   0x10

#define SKW_HE_MAC_CAP4_AMDSU_IN_AMPDU                            0x40

#define SKW_HE_PHY_CAP0_DUAL_BAND                                 0x01
#define SKW_HE_PHY_CAP0_CHANNEL_WIDTH_SET_40MHZ_IN_2G             0x02
#define SKW_HE_PHY_CAP0_CHANNEL_WIDTH_SET_40MHZ_80MHZ_IN_5G       0x04
#define SKW_HE_PHY_CAP0_CHANNEL_WIDTH_SET_160MHZ_IN_5G            0x08
#define SKW_HE_PHY_CAP0_CHANNEL_WIDTH_SET_80PLUS80_MHZ_IN_5G      0x10

#define SKW_HE_PHY_CAP1_PREAMBLE_PUNC_RX_MASK                     0x0f
#define SKW_HE_PHY_CAP1_DEVICE_CLASS_A                            0x10
#define SKW_HE_PHY_CAP1_LDPC_CODING_IN_PAYLOAD                    0x20
#define SKW_HE_PHY_CAP1_MIDAMBLE_RX_TX_MAX_NSTS                   0X80

#define SKW_HE_PHY_CAP2_NDP_4x_LTF_AND_3_2US                      0x02
#define SKW_HE_PHY_CAP2_STBC_TX_UNDER_80MHZ                       0x04
#define SKW_HE_PHY_CAP2_STBC_RX_UNDER_80MHZ                       0x08
#define SKW_HE_PHY_CAP2_UL_MU_FULL_MU_MIMO                        0x40
#define SKW_HE_PHY_CAP2_UL_MU_PARTIAL_MU_MIMO                     0x80

#define SKW_WLAN_REASON_TDLS_TEARDOWN_UNREACHABLE                 25
#define SKW_WLAN_CATEGORY_RADIO_MEASUREMENT                       5

#define SKW_IEEE80211_CHAN_NO_20MHZ                               BIT(11)
/* end of compat for ieee80211 */

#define SKW_WIPHY_FEATURE_SCAN_RANDOM_MAC                         BIT(29)
#define SKW_EXT_CAPA_BSS_TRANSITION                               19
#define SKW_EXT_CAPA_MBSSID                                       22
#define SKW_EXT_CAPA_TDLS_SUPPORT                                 37
#define SKW_EXT_CAPA_TWT_REQ_SUPPORT                              77

#define SKW_BSS_MEMBERSHIP_SELECTOR_HT_PHY                        127
#define SKW_BSS_MEMBERSHIP_SELECTOR_VHT_PHY                       126

#ifndef MIN_NICE
#define MIN_NICE                                                  -20
#endif

#ifndef TASK_IDLE
#define TASK_IDLE                                                 TASK_INTERRUPTIBLE
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
#define SKW_BSS_TYPE_ESS                              IEEE80211_BSS_TYPE_ESS
#define SKW_BSS_TYPE_IBSS                             IEEE80211_BSS_TYPE_IBSS
#define SKW_PRIVACY_ESS_ANY                           IEEE80211_PRIVACY_ANY
#define SKW_PRIVACY_IBSS_ANY                          IEEE80211_PRIVACY_ANY
#else
#define SKW_BSS_TYPE_ESS                              WLAN_CAPABILITY_ESS
#define SKW_BSS_TYPE_IBSS                             WLAN_CAPABILITY_IBSS
#define SKW_PRIVACY_ESS_ANY                           WLAN_CAPABILITY_ESS
#define SKW_PRIVACY_IBSS_ANY                          WLAN_CAPABILITY_ESS
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
#define SKW_PASSIVE_SCAN (IEEE80211_CHAN_NO_IR | IEEE80211_CHAN_RADAR)
#else
#define SKW_PASSIVE_SCAN IEEE80211_CHAN_PASSIVE_SCAN
#endif

#define skw_from_timer(var, callback_timer, timer_fieldname) \
	container_of(callback_timer, typeof(*var), timer_fieldname)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
#define skw_compat_setup_timer(timer, fn) \
	timer_setup(timer, fn, 0)
#else
typedef void (*tfunc)(unsigned long);
#define skw_compat_setup_timer(timer, fn) \
	setup_timer(timer, (tfunc)fn, (unsigned long)timer)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 12, 0)
enum nl80211_bss_scan_width {
	NL80211_BSS_CHAN_WIDTH_20,
	NL80211_BSS_CHAN_WIDTH_10,
	NL80211_BSS_CHAN_WIDTH_5,
};
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
#define NUM_NL80211_BANDS    3
#endif

#if (KERNEL_VERSION(4, 6, 0) <= LINUX_VERSION_CODE)
#define SKW_IS_COMPAT_TASK in_compat_syscall
#else
#define SKW_IS_COMPAT_TASK is_compat_task
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0)
/**
 * ether_addr_copy - Copy an Ethernet address
 * @dst: Pointer to a six-byte array Ethernet address destination
 * @src: Pointer to a six-byte array Ethernet address source
 *
 * Please note: dst & src must both be aligned to u16.
 */
static inline void ether_addr_copy(u8 *dst, const u8 *src)
{
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)
	*(u32 *)dst = *(const u32 *)src;
	*(u16 *)(dst + 4) = *(const u16 *)(src + 4);
#else
	u16 *a = (u16 *)dst;
	const u16 *b = (const u16 *)src;

	a[0] = b[0];
	a[1] = b[1];
	a[2] = b[2];
#endif
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
static inline struct sk_buff *
skw_compat_vendor_event_alloc(struct wiphy *wiphy, struct wireless_dev *wdev,
			int roxlen, int event_idx, gfp_t gfp)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
	return cfg80211_vendor_event_alloc(wiphy, wdev, roxlen, event_idx, gfp);
#else
	return cfg80211_vendor_event_alloc(wiphy, roxlen, event_idx, gfp);
#endif
}
#endif

static inline void skw_compat_cqm_rssi_notify(struct net_device *dev,
			enum nl80211_cqm_rssi_threshold_event rssi_event,
			s32 rssi_level, gfp_t gfp)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
	cfg80211_cqm_rssi_notify(dev, rssi_event, rssi_level, gfp);
#else
	cfg80211_cqm_rssi_notify(dev, rssi_event, gfp);
#endif
}

static inline void skw_compat_page_frag_free(void *addr)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	page_frag_free(addr);
#else
	put_page(virt_to_head_page(addr));
#endif
}

static inline void
skw_compat_scan_done(struct cfg80211_scan_request *req, bool aborted)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
	struct cfg80211_scan_info info = {
		.aborted = aborted,
	};

	cfg80211_scan_done(req, &info);
#else
	cfg80211_scan_done(req, aborted);
#endif
}

static inline void skw_compat_disconnected(struct net_device *ndev, u16 reason,
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 16, 0)
				   u8 *ie,
#else
				   const u8 *ie,
#endif
				   size_t ie_len,
				   bool locally_generated, gfp_t gfp)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
	cfg80211_disconnected(ndev, reason, ie, ie_len, locally_generated, gfp);
#else
	cfg80211_disconnected(ndev, reason, ie, ie_len, gfp);
#endif
}

static inline void skw_compat_cfg80211_roamed(struct net_device *dev,
			const u8 *bssid, const u8 *req_ie,
			size_t req_ie_len, const u8 *resp_ie,
			size_t resp_ie_len, gfp_t gfp)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
	struct cfg80211_roam_info roam_info = {
		.bss = NULL,
		.bssid = bssid,
		.req_ie = req_ie,
		.req_ie_len = req_ie_len,
		.resp_ie = resp_ie,
		.resp_ie_len = resp_ie_len,
	};

	cfg80211_roamed(dev, &roam_info, gfp);
#else
	// fixme:
	// fix channel
	cfg80211_roamed(dev, NULL, bssid, req_ie, req_ie_len,
			resp_ie, resp_ie_len, gfp);
#endif
}

static inline bool skw_compat_reg_can_beacon(struct wiphy *wiphy,
			     struct cfg80211_chan_def *chandef,
			     enum nl80211_iftype iftype)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
	return cfg80211_reg_can_beacon_relax(wiphy, chandef, iftype);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 2, 0) && LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0)
	return cfg80211_reg_can_beacon(wiphy, chandef, iftype);
#else
	return cfg80211_reg_can_beacon(wiphy, chandef);
#endif
}

static inline unsigned int
skw_compat_classify8021d(struct sk_buff *skb, void *qos_map)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0)
	return cfg80211_classify8021d(skb);
#else
	return cfg80211_classify8021d(skb, qos_map);
#endif
}

static inline void skw_compat_rx_assoc_resp(struct net_device *dev,
			struct cfg80211_bss *bss, const u8 *buf, size_t len,
			int uapsd, const u8 *req_ie, size_t req_ie_len)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
	cfg80211_rx_assoc_resp(dev, bss, buf, len, uapsd, req_ie, req_ie_len);
#elif defined SKW_RX_ASSOC_RESP_EXT
	cfg80211_rx_assoc_resp_ext(dev, bss, buf, len, uapsd, req_ie, req_ie_len);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0)
	cfg80211_rx_assoc_resp(dev, bss, buf, len, uapsd);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
	cfg80211_rx_assoc_resp(dev, bss, buf, len);
#else
	cfg80211_send_rx_assoc(dev, bss, buf, len);
#endif
}

static inline void
skw_compat_rx_mlme_mgmt(struct net_device *dev, void *buf, size_t len)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
	cfg80211_rx_mlme_mgmt(dev, buf, len);
#else
	struct ieee80211_mgmt *mgmt = buf;

	if (ieee80211_is_auth(mgmt->frame_control))
		cfg80211_send_rx_auth(dev, buf, len);
	else if (ieee80211_is_deauth(mgmt->frame_control))
		cfg80211_send_deauth(dev, buf, len);
	else if (ieee80211_is_disassoc(mgmt->frame_control))
		cfg80211_send_disassoc(dev, buf, len);
#endif
}

static inline const u8 *skw_compat_bssid(struct cfg80211_connect_params *req)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0)
	return req->bssid ? req->bssid : req->bssid_hint;
#else
	return req->bssid;
#endif
}

static inline struct ieee80211_channel *
skw_compat_channel(struct cfg80211_connect_params *req)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0)
	return req->channel ? req->channel : req->channel_hint;
#else
	return req->channel;
#endif
}

static inline int skw_compat_check_combs(struct wiphy *wiphy, int nr_channels,
				u8 radar, int type_num[NUM_NL80211_IFTYPES])
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	struct iface_combination_params params = {
		.num_different_channels = nr_channels,
		.radar_detect = radar,
	};

	memcpy(params.iftype_num, type_num, NUM_NL80211_IFTYPES * sizeof(int));

	return cfg80211_check_combinations(wiphy, &params);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0)
	return cfg80211_check_combinations(wiphy, nr_channels, radar, type_num);
#else
	// TODO:
	// implement function to check combinations
	return 0;
#endif
}

static inline void skw_compat_auth_timeout(struct net_device *dev, const u8 *addr)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
	cfg80211_auth_timeout(dev, addr);
#else
	cfg80211_send_auth_timeout(dev, addr);
#endif
}

static inline void skw_compat_assoc_timeout(struct net_device *dev,
					struct cfg80211_bss *bss)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
	cfg80211_assoc_timeout(dev, bss);
#else
	cfg80211_send_assoc_timeout(dev, bss->bssid);
#endif
}

static inline void skw_cfg80211_tx_mlme_mgmt(struct net_device *dev,
				const u8 *buf, size_t len)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0)
	struct ieee80211_mgmt *mgmt = (void *)buf;

	if (ieee80211_is_deauth(mgmt->frame_control))
		cfg80211_send_deauth(dev, buf, len);
	else
		cfg80211_send_disassoc(dev, buf, len);
#else
	cfg80211_tx_mlme_mgmt(dev, buf, len);
#endif
}

static inline void skw_compat_rtc_time_to_tm(unsigned long time, struct rtc_time *tm)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
	rtc_time_to_tm(time, tm);
#else
	rtc_time64_to_tm(time, tm);
#endif
}

static inline bool skw_compat_cfg80211_rx_mgmt(struct wireless_dev *wdev,
				int freq, int sig_dbm, const u8 *buf,
				size_t len, u32 flags, gfp_t gfp)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 12, 0)
	return cfg80211_rx_mgmt(wdev, freq, sig_dbm, buf, len, gfp);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 0)
	return cfg80211_rx_mgmt(wdev, freq, sig_dbm, buf, len, flags, gfp);
#else
	return cfg80211_rx_mgmt(wdev, freq, sig_dbm, buf, len, flags);
#endif
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 14, 0)
#if NR_CPUS == 1
static inline unsigned int cpumask_last(const struct cpumask *srcp)
{
	return 0;
}
#else
static inline unsigned int cpumask_last(const struct cpumask *srcp)
{
	return find_last_bit(cpumask_bits(srcp), nr_cpumask_bits);
}
#endif
#endif

#endif
