/* Copyright (c) 2016-2018, Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/delay.h>
#include <linux/extcon-provider.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/power_supply.h>

#if 0 /* PEGA: not supported */
#include <linux/usb/class-dual-role.h>
#include <linux/usb/usbpd.h>
#endif

#include "fusb30x_global.h"
#include "platform_helpers.h"
#include "platform_usbpd.h"
#include "../core/core.h"

#if 0 /* PEGA: not supported */
/* add include for typec port class */
#include "../../../pd/usbpd.h"
#endif

static int usb_state = 0;

extern void stop_usb_host(struct fusb30x_chip* chip);

#if 0 /* PEGA: not supported */
static enum dual_role_property usbpd_dr_properties[] = {
	DUAL_ROLE_PROP_SUPPORTED_MODES,
	DUAL_ROLE_PROP_MODE,
	DUAL_ROLE_PROP_PR,
	DUAL_ROLE_PROP_DR,
};

static void fusb_force_source(struct dual_role_phy_instance *dual_role)
{
	struct fusb30x_chip* chip = fusb30x_GetChip();
	pr_debug("FUSB - %s\n", __func__);
	core_set_source(&chip->port);

	if (dual_role)
		dual_role_instance_changed(dual_role);
}

static void fusb_force_sink(struct dual_role_phy_instance *dual_role)
{
	struct fusb30x_chip* chip = fusb30x_GetChip();
	pr_debug("FUSB - %s\n", __func__);
	core_set_sink(&chip->port);
	if (dual_role)
		dual_role_instance_changed(dual_role);
}

static unsigned int fusb_get_dual_role_mode(void)
{
	struct fusb30x_chip* chip = fusb30x_GetChip();
	int mode = DUAL_ROLE_PROP_MODE_NONE;

	if (chip->port.CCPin != CCNone) {
		if (chip->port.sourceOrSink == SOURCE) {
			mode = DUAL_ROLE_PROP_MODE_DFP;
			pr_debug("FUSB - %s DUAL_ROLE_PROP_MODE_DFP, mode = %d\n",
					__func__, mode);
		} else {
			mode = DUAL_ROLE_PROP_MODE_UFP;
			pr_debug("FUSB - %s DUAL_ROLE_PROP_MODE_UFP, mode = %d\n",
					__func__, mode);
		}
	}
	pr_debug("FUSB - %s mode = %d\n", __func__, mode);
	return mode;
}

static unsigned int fusb_get_dual_role_power(void)
{
	struct fusb30x_chip* chip = fusb30x_GetChip();
	int current_pr = DUAL_ROLE_PROP_PR_NONE;

	pr_debug("FUSB %s\n", __func__);

	if (chip->port.CCPin != CCNone) {
		if (chip->port.sourceOrSink == SOURCE) {
			current_pr = DUAL_ROLE_PROP_PR_SRC;
			pr_debug("FUSB - %s DUAL_ROLE_PROP_PR_SRC, current_pr = %d\n",
					__func__, current_pr);
		} else {
			current_pr = DUAL_ROLE_PROP_PR_SNK;
			pr_debug("FUSB - %s DUAL_ROLE_PROP_PR_SNK, current_pr = %d\n",
					__func__, current_pr);
		}
	}
	pr_debug("FUSB - %s current_pr = %d\n", __func__, current_pr);
	return current_pr;
}

static unsigned int fusb_get_dual_role_data(void)
{
	struct fusb30x_chip* chip = fusb30x_GetChip();
	int current_dr = DUAL_ROLE_PROP_DR_NONE;

	pr_debug("FUSB %s\n", __func__);

	if (chip->port.CCPin != CCNone) {
		if (chip->port.PolicyIsDFP) {
			current_dr = DUAL_ROLE_PROP_DR_HOST;
			pr_debug("FUSB - %s DUAL_ROLE_PROP_DR_HOST, current_dr = %d\n",
					__func__, current_dr);
		} else {
			current_dr = DUAL_ROLE_PROP_DR_DEVICE;
			pr_debug("FUSB - %s DUAL_ROLE_PROP_DR_DEVICE, current_dr = %d\n",
					__func__, current_dr);
		}
	}
	pr_debug("FUSB - %s current_dr = %d\n", __func__, current_dr);
	return current_dr;
}

static int usbpd_dr_get_property(struct dual_role_phy_instance *dual_role,
		enum dual_role_property prop, unsigned int *val)
{
	unsigned int mode = DUAL_ROLE_PROP_MODE_NONE;
	switch (prop) {
	case DUAL_ROLE_PROP_MODE:
		mode = fusb_get_dual_role_mode();
		*val = mode;
		break;
	case DUAL_ROLE_PROP_PR:
		mode = fusb_get_dual_role_power();
		*val = mode;
		break;
	case DUAL_ROLE_PROP_DR:
		mode = fusb_get_dual_role_data();
		*val = mode;
		break;
	default:
		pr_err("FUSB unsupported property %d\n", prop);
		return -ENODATA;
	}
	pr_debug("FUSB %s + prop=%d, val=%d\n", __func__, prop, *val);
	return 0;
}

static int usbpd_dr_set_property(struct dual_role_phy_instance *dual_role,
		enum dual_role_property prop, const unsigned int *val)
{
	struct fusb30x_chip* chip = fusb30x_GetChip();
	unsigned int mode = fusb_get_dual_role_mode();

	pr_debug("FUSB %s\n", __func__);

	if (!chip) {
		pr_err("FUSB %s - Error: Chip structure is NULL!\n", __func__);
		return -1;
	}
	pr_debug("FUSB %s + prop=%d,val=%d,mode=%d\n",
			__func__, prop, *val, mode);
	switch (prop) {
	case DUAL_ROLE_PROP_MODE:
		if (*val != mode) {
			if (mode == DUAL_ROLE_PROP_MODE_UFP)
				fusb_force_source(dual_role);
			else if (mode == DUAL_ROLE_PROP_MODE_DFP)
				fusb_force_sink(dual_role);
		}
		break;
	case DUAL_ROLE_PROP_PR:
		pr_debug("FUSB - %s DUAL_ROLE_PROP_PR\n", __func__);
		break;
	case DUAL_ROLE_PROP_DR:
		pr_debug("FUSB - %s DUAL_ROLE_PROP_DR\n", __func__);
		break;
	default:
		pr_debug("FUSB - %s default case\n", __func__);
		break;
	}
	return 0;
}

static int usbpd_dr_prop_writeable(struct dual_role_phy_instance *dual_role,
		enum dual_role_property prop)
{
	pr_debug("FUSB - %s\n", __func__);
	switch (prop) {
	case DUAL_ROLE_PROP_MODE:
		return 1;
		break;
	case DUAL_ROLE_PROP_DR:
	case DUAL_ROLE_PROP_PR:
		return 0;
		break;
	default:
		break;
	}
	return 1;
}
#endif

/* add api for typec port class */
int fusbpd_typec_dr_set(const struct typec_capability *cap,
	enum typec_data_role role)
{
	struct fusb30x_chip* chip = container_of(cap, struct fusb30x_chip, typec_caps);
	pr_err("FUSB-fusbpd_typec_dr_set: Setting data role to %d\n", role);
	pr_err("FUSB-%s PolicyIsDFP=%d\n", __func__, chip->port.PolicyIsDFP);
	if ( cap == NULL) {
		pr_err("fusbpd_typec_dr_set cap is NULL return -1\n");
		return -1;
	}
	if (role == TYPEC_HOST) {
		if (chip->port.PolicyIsDFP == FALSE) {
			if (chip->port.PolicyState == peSinkReady) {
				SetPEState(&chip->port, peSinkSendDRSwap);
			} else if (chip->port.PolicyState == peSourceReady) {
				SetPEState(&chip->port, peSourceSendDRSwap);
			}
			chip->port.PEIdle = FALSE;
			queue_work(chip->highpri_wq, &chip->sm_worker);
			pr_err("FUSB %s-%d: run pe---SendDRSwap\n", __func__, __LINE__);
		}
	} else if (role == TYPEC_DEVICE) {
		if (chip->port.PolicyIsDFP == TRUE) {
			if (chip->port.PolicyState == peSinkReady) {
				SetPEState(&chip->port, peSinkSendDRSwap);
			} else if (chip->port.PolicyState == peSourceReady) {
				SetPEState(&chip->port, peSourceSendDRSwap);
			}
			chip->port.PEIdle = FALSE;
			queue_work(chip->highpri_wq, &chip->sm_worker);
			pr_err("FUSB %s-%d: run pe---SendDRSwap\n", __func__, __LINE__);
		}
	}
	return 0;
}

int fusbpd_typec_pr_set(const struct typec_capability *cap,
	enum typec_role role)
{
	struct fusb30x_chip* chip = container_of(cap, struct fusb30x_chip, typec_caps);
	pr_err("fusbpd_typec_pr_set: Setting power role to %d\n", role);

	pr_err("FUSB-%s PolicyIsSource=%d, PolicyState=%d\n", __func__,
			chip->port.PolicyIsSource, chip->port.PolicyState);
	if ( cap == NULL) {
		pr_err("fusbpd_typec_pr_set cap is NULL return -1\n");
		return -1;
	}
	if (role == TYPEC_SOURCE) {
		if (chip->port.PolicyState == peSinkReady) {
			if (chip->port.PolicyIsSource == FALSE) {
				SetPEState(&chip->port, peSinkSendPRSwap);
				chip->port.PEIdle = FALSE;
				queue_work(chip->highpri_wq, &chip->sm_worker);
				pr_err("FUSB %s: run peSinkSendPRSwap\n", __func__);
				}
			} else {
			core_set_try_src(&chip->port);
		}
		pr_err("FUSB %s start try source or prswap to source \n", __func__);
	} else if(role == TYPEC_SINK) {
		if (chip->port.PolicyState == peSourceReady) {
			if (chip->port.PolicyIsSource == TRUE) {
				SetPEState(&chip->port, peSourceSendPRSwap);
				chip->port.PEIdle = FALSE;
				queue_work(chip->highpri_wq, &chip->sm_worker);
				pr_err("FUSB %s: run peSourceSendPRSwap\n", __func__);
			}
		} else {
			core_set_try_snk(&chip->port);
		}
		pr_err("FUSB %s start try sink or prswap to sink \n", __func__);
	}
	return 0;
}

int fusbpd_typec_port_type_set(const struct typec_capability *cap,
	enum typec_port_type type)
{
	struct fusb30x_chip* chip = fusb30x_GetChip();
	if ( cap == NULL) {
		pr_err("fusbpd_typec_port_type_set cap is NULL return -1\n");
		return -1;
	}
	pr_err("FUSB %s:power role state PolicyIsSource = %d\n",
		__func__, chip->port.PolicyIsSource);
	pr_err("FUSB %s:new type=%d\n", __func__, type);
	pr_info("FUSB %s:pd_contract=%d,PolicyState=%d\n",
		__func__, chip->port.PolicyHasContract,chip->port.PolicyState);

	if (type == TYPEC_PORT_DRP) {
		return 0;
	} else if (type == TYPEC_PORT_SNK) {
			if (chip->port.PolicyState == peSourceReady) {
				if (chip->port.PolicyIsSource == TRUE) {
					SetPEState(&chip->port, peSourceSendPRSwap);
					chip->port.PEIdle = FALSE;
					queue_work(chip->highpri_wq, &chip->sm_worker);
					pr_err("FUSB %s: run peSourceSendPRSwap\n", __func__);
				}
			} else {
				core_set_try_snk(&chip->port);
			}
			pr_err("FUSB %s start try sink or prswap to sink \n", __func__);
	} else if (type == TYPEC_PORT_SRC) {
		pr_err(" FUSB %s chip->port.PolicyHasContract=%d \n", __func__,chip->port.PolicyHasContract);
		if (chip->port.PolicyState == peSinkReady){
			if (chip->port.PolicyIsSource == FALSE) {
				SetPEState(&chip->port, peSinkSendPRSwap);
				chip->port.PEIdle = FALSE;
				queue_work(chip->highpri_wq, &chip->sm_worker);
				pr_err("FUSB %s: run peSinkSendPRSwap\n", __func__);
			}
		} else {
			core_set_try_src(&chip->port);
		}
		pr_err("FUSB %s start try source or prswap to source \n", __func__);
	}
	return 0;
 }

struct usbpd *fusb30x_usbpd_create(struct device *parent)
{
	struct usbpd *pd;

	pd = devm_kzalloc(parent, sizeof(*pd), GFP_KERNEL);
	if (!pd)
		return ERR_PTR(-ENOMEM);

#if 0 /* PEGA: not supported */
	mutex_init(&pd->svid_handler_lock);
	INIT_LIST_HEAD(&pd->svid_handlers);

	pd->dr_desc.name = "otg_default";
	pd->dr_desc.supported_modes = DUAL_ROLE_SUPPORTED_MODES_DFP_AND_UFP;
	pd->dr_desc.properties = usbpd_dr_properties;
	pd->dr_desc.num_properties = ARRAY_SIZE(usbpd_dr_properties);
	pd->dr_desc.get_property = usbpd_dr_get_property;
	pd->dr_desc.set_property = usbpd_dr_set_property;
	pd->dr_desc.property_is_writeable = usbpd_dr_prop_writeable;

	pd->dual_role = devm_dual_role_instance_register(parent,
		&pd->dr_desc);
	if (IS_ERR(pd->dual_role)) {
		pr_info("FUSB could not register dual_role instance\n");
	} else {
		pd->dual_role->drv_data = pd;
	}
#endif

	pr_info("FUSB %s\n", __func__);

	return pd;
}

void fusb30x_usbpd_destroy(struct usbpd *pd)
{
}

void reset_usbpd(struct usbpd *pd)
{
#if 0 /* PEGA: not supported */
	pd->ss_lane_svid = 0x0;
#endif
}

#if 0 /* PEGA: not supported */
/**
 * This API allows client driver to request for releasing SS lanes. It should
 * not be called from atomic context.
 */
int usbpd_release_ss_lane(struct usbpd *pd,
				struct usbpd_svid_handler *handler)
{
	int ret = 0;
	struct fusb30x_chip* chip = fusb30x_GetChip();
	pr_debug("FUSB - %s +++\n", __func__);

	if (!handler || !chip) {
		pr_err("FUSB - %s ss lanes are already used by %d\n",
			__func__, chip->usbpd->ss_lane_svid);
		return -EINVAL;	
	}

	pr_debug("FUSB %s handler:%pK svid:%d", __func__, handler, handler->svid);
	/*
	 * If USB SS lanes are already used by one client, and other client is
	 * requesting for same or same client requesting again, return -EBUSY.
	 */
	if (chip->usbpd->ss_lane_svid) {
		pr_err("FUSB %s: ss_lanes are already used by %d",
				__func__, chip->usbpd->ss_lane_svid);
		ret = -EBUSY;
		goto err_exit;
	}

	extcon_blocking_sync(chip->extcon, EXTCON_USB_HOST, 1);
	stop_usb_host(chip);

	/* blocks until USB host is completely stopped */
	ret = extcon_blocking_sync(chip->extcon, EXTCON_USB_HOST, 0);
	if (ret) {
		pr_err("FUSB %s err %d stopping host", __func__, ret);
		goto err_exit;
	}

	start_usb_host(chip, false);
	extcon_blocking_sync(chip->extcon, EXTCON_USB_HOST, 1);
	chip->usbpd->ss_lane_svid = handler->svid;

err_exit:
	return ret;
}

static struct usbpd_svid_handler *find_svid_handler(struct usbpd *pd, u16 svid)
{
	struct usbpd_svid_handler *handler;

	mutex_lock(&pd->svid_handler_lock);
	list_for_each_entry(handler, &pd->svid_handlers, entry) {
		if (svid == handler->svid) {
			mutex_unlock(&pd->svid_handler_lock);
			return handler;
		}
	}
	mutex_unlock(&pd->svid_handler_lock);
	return NULL;
}

struct usbpd *fusb30x_devm_usbpd_get_by_phandle(struct device *dev,
		const char *phandle)
{
	struct fusb30x_chip* chip = fusb30x_GetChip();

	pr_debug("FUSB enter %s\n", __func__);

	if (!chip) {
		pr_err("FUSB Chip not ready!\n");
		return ERR_PTR(-EAGAIN);
	}
	return chip->usbpd;
}

static int usbpd_dp_release_ss_lane(struct usbpd *pd,
	struct usbpd_svid_handler *handler)
{
	pr_info("FUSB dp request us to release sslane\n");
	return 0;
}

int fusb30x_usbpd_register_svid(struct usbpd *pd, struct usbpd_svid_handler *hdlr)
{
	struct fusb30x_chip* chip = fusb30x_GetChip();
	int ret/*,i*/;

	if (find_svid_handler(pd, hdlr->svid)) {
		pr_err("FUSB SVID 0x%04x already registered\n",
			hdlr->svid);
		return -EINVAL;
	}

	/* require connect/disconnect callbacks be implemented */
	if (!hdlr->connect || !hdlr->disconnect) {
		pr_err("FUSB SVID 0x%04x connect/disconnect must be non-NULL\n",
				hdlr->svid);
		return -EINVAL;
	}

	pr_debug("FUSB registered handler(%pK) for SVID 0x%04x\n",
							hdlr, hdlr->svid);
	mutex_lock(&pd->svid_handler_lock);
	list_add_tail(&hdlr->entry, &pd->svid_handlers);
	mutex_unlock(&pd->svid_handler_lock);
	hdlr->request_usb_ss_lane = usbpd_dp_release_ss_lane;

	/* reset fusb302 */
	fusb_reset();

	/* already connected with this SVID discovered? */
	if (!chip) {
		pr_err("FUSB Chip not ready!\n");
		return -EINVAL;
	}

	/* need to check with dp team
	 * get better solution
	 * to cover no dp function
	 */

	/* Enable interrupts after successful core/GPIO initialization */
    ret = fusb_EnableInterrupts();
    if (ret)
    {
        pr_err("FUSB  %s - Error: Unable to enable interrupts! Error code: %d\n", __func__, ret);
        return -EIO;
    }

    /* Initialize the core and enable the state machine (NOTE: timer and GPIO must be initialized by now)
    *  Interrupt must be enabled before starting 302 initialization */
    fusb_InitializeCore();
    pr_info("FUSB  %s - Core is initialized!\n", __func__);
#if 0
	if (chip->port.svid_discvry_done) {
		for (i = 0; i < chip->port.core_svid_info.num_svids; i++) {
			if (chip->port.core_svid_info.svids[i] == hdlr->svid) {
				hdlr->connect(hdlr, chip->usbpd->peer_usb_comm);
				hdlr->discovered = true;

				ret = usbpd_release_ss_lane(chip->usbpd, hdlr);
				pr_info("FUSB - %s: usbpd_release_ss_lane return ret=%d\n",
					__func__, ret);
				chip->usbpd->block_dp_event = FALSE;
				break;
			}
		}
	}
#endif

	return 0;
}
EXPORT_SYMBOL(fusb30x_usbpd_register_svid);

void fusb30x_usbpd_unregister_svid(struct usbpd *pd, struct usbpd_svid_handler *hdlr)
{

	pr_info("FUSB unregistered handler(%pK) for SVID 0x%04x\n",
							hdlr, hdlr->svid);
	mutex_lock(&pd->svid_handler_lock);
	list_del_init(&hdlr->entry);
	mutex_unlock(&pd->svid_handler_lock);
}
EXPORT_SYMBOL(fusb30x_usbpd_unregister_svid);
#endif

int fusb30x_usbpd_send_vdm(struct usbpd *pd, u32 vdm_hdr, const u32 *vdos, int num_vdos)
{
	struct Port* port;
	int i = 0;
	struct fusb30x_chip* chip = fusb30x_GetChip();

	pr_info("FUSB enter: %s, vdm_hdr=%8x\n", __func__, vdm_hdr);
	if (!chip || !chip->port.PolicyHasContract) {
		pr_info("FUSB:%s No PDPHY or PD isn't supported\n");
		return -1;
	}
	port = &chip->port;

	port->PolicyMsgTxSop = SOP_TYPE_SOP;

	port->PDTransmitHeader.word = 0;
	port->PDTransmitHeader.MessageType = DMTVenderDefined;
	port->PDTransmitHeader.NumDataObjects = num_vdos + 1;
	port->PDTransmitHeader.PortDataRole = port->PolicyIsDFP;
	port->PDTransmitHeader.PortPowerRole = port->PolicyIsSource;
	port->PDTransmitHeader.SpecRevision = DPM_SpecRev(port, SOP_TYPE_SOP);

	port->PDTransmitObjects[0].object = vdm_hdr;
	/* Data objects */
	for (i = 1; i < port->PDTransmitHeader.NumDataObjects; ++i)
	{
		port->PDTransmitObjects[i].object = *vdos++;
	}
	port->USBPDTxFlag = TRUE;
	return 0;
}
EXPORT_SYMBOL(fusb30x_usbpd_send_vdm);

#if 0 /* PEGA: not supported */
#define SVDM_HDR(svid, ver, obj, cmd_type, cmd) \
	(((svid) << 16) | (1 << 15) | ((ver) << 13) \
	| ((obj) << 8) | ((cmd_type) << 6) | (cmd))

int fusb30x_usbpd_send_svdm(struct usbpd *pd, u16 svid, u8 cmd,
		enum usbpd_svdm_cmd_type cmd_type, int obj_pos,
		const u32 *vdos, int num_vdos)
{
	u32 svdm_hdr = SVDM_HDR(svid, 0, obj_pos, cmd_type, cmd);
	return fusb30x_usbpd_send_vdm(pd, svdm_hdr, vdos, num_vdos);
}
EXPORT_SYMBOL(fusb30x_usbpd_send_svdm);

enum plug_orientation fusb30x_usbpd_get_plug_orientation(struct usbpd *pd)
{
	struct fusb30x_chip* chip = fusb30x_GetChip();
	return (int)chip->port.CCPin;
}
#endif

void stop_usb_host(struct fusb30x_chip* chip)
{
	pr_info("FUSB - %s\n", __func__);
	extcon_set_state_sync(chip->extcon, EXTCON_USB_HOST, 0);
}

void start_usb_host(struct fusb30x_chip* chip, bool ss)
{
	union extcon_property_value val;
	
	pr_info("FUSB - %s, ss=%d\n", __func__, ss);

	val.intval = (chip->port.CCPin == CC2);
	extcon_set_property(chip->extcon, EXTCON_USB_HOST,
			EXTCON_PROP_USB_TYPEC_POLARITY, val);

	val.intval = ss;
	extcon_set_property(chip->extcon, EXTCON_USB_HOST,
			EXTCON_PROP_USB_SS, val);

	extcon_set_state_sync(chip->extcon, EXTCON_USB_HOST, 1);
}

void stop_usb_peripheral(struct fusb30x_chip* chip)
{
	pr_info("FUSB - %s\n", __func__);
	extcon_set_state_sync(chip->extcon, EXTCON_USB, 0);
}

void start_usb_peripheral(struct fusb30x_chip* chip)
{
	union extcon_property_value val;
	
	pr_info("FUSB - %s\n", __func__);

	val.intval = (chip->port.CCPin == CC2);
	extcon_set_property(chip->extcon, EXTCON_USB,
			EXTCON_PROP_USB_TYPEC_POLARITY, val);
	pr_debug("FUSB - %s, EXTCON_PROP_USB_TYPEC_POLARITY=%d\n",
		__func__, val.intval);

	val.intval = 1;
	extcon_set_property(chip->extcon, EXTCON_USB, EXTCON_PROP_USB_SS, val);
	pr_debug("FUSB - %s, EXTCON_PROP_USB_SS=%d\n", __func__, val.intval);

	val.intval = chip->port.SinkCurrent > utccDefault ? 1 : 0;
	extcon_set_property(chip->extcon, EXTCON_USB,
		EXTCON_PROP_USB_TYPEC_MED_HIGH_CURRENT, val);
	pr_debug("FUSB - %s, EXTCON_PROP_USB_TYPEC_MED_HIGH_CURRENT=%d\n",
		__func__, val.intval);

	extcon_set_state_sync(chip->extcon, EXTCON_USB, 1);
}

void handle_core_event(FSC_U32 event, FSC_U8 portId,
		void *usr_ctx, void *app_ctx)
{
	int ret = 0;
#if 0 /* PEGA: not supported */
	int i = 0;
	doDataObject_t vdmh_in = { 0 };
	FSC_U32* arr_in = NULL;
	struct usbpd_svid_handler* handler = NULL;
	union power_supply_propval val = {0};
#endif
	static bool start_power_swap = FALSE;
	FSC_U32 set_voltage;
	FSC_U32 op_current;
	struct fusb30x_chip* chip = fusb30x_GetChip();
	chip->count_MAX = 100;

	if (!chip) {
		pr_err("FUSB %s - Error: Chip structure is NULL!\n", __func__);
		return;
	}

	pr_debug("FUSB %s - Notice, event=0x%x\n", __func__, event);
	switch (event) {
	case CC1_ORIENT:
	case CC2_ORIENT:
		pr_info("FUSB %s:CC Changed=0x%x\n", __func__, event);
		if (chip->port.sourceOrSink == SINK) {
			chip->count = 0;
#if 0 /* PEGA: not supported */
			ret = power_supply_get_property(chip->usbpd->usb_psy,
				POWER_SUPPLY_PROP_REAL_TYPE,&val);
			if (ret < 0 || val.intval == POWER_SUPPLY_TYPE_UNKNOWN)
				queue_delayed_work(chip->pd_workqueue_struct,
						&chip->pd_delayed_work, msecs_to_jiffies(100));
#endif
			usb_state = 1;
			pr_debug("FUSB %s start_usb_peripheral\n", __func__);

			/* typec mode update */
#if 0 /* PEGA: not supported */
			chip->current_pr = PR_SINK;
			chip->current_dr = DR_UFP;
#endif
			typec_set_data_role(chip->typec_port, TYPEC_DEVICE);
			typec_set_pwr_role(chip->typec_port, TYPEC_SINK);
			if (!chip->partner) {
				typec_set_pwr_opmode(chip->typec_port,TYPEC_PWR_MODE_1_5A);
				memset(&chip->partner_identity, 0, sizeof(chip->partner_identity));
				chip->partner_desc.usb_pd = false;
				chip->partner_desc.accessory = TYPEC_ACCESSORY_NONE;
				chip->partner = typec_register_partner(chip->typec_port,
					&chip->partner_desc);
			}
#if 0 /* PEGA: not supported */
			val.intval = POWER_SUPPLY_TYPEC_PR_SINK;
			power_supply_set_property(chip->usbpd->usb_psy,
				POWER_SUPPLY_PROP_TYPEC_POWER_ROLE, &val);
#endif
		} else if (chip->port.sourceOrSink == SOURCE) {
			start_usb_host(chip, true);
			usb_state = 2;
#if 0 /* PEGA: not supported */
			chip->usbpd->ss_lane_svid = 0x0;
#endif
			pr_debug("FUSB %s start_usb_host\n", __func__);

			/* typec mode update */
#if 0 /* PEGA: not supported */
			chip->current_pr = PR_SRC;
			chip->current_dr = DR_DFP;
#endif
			typec_set_data_role(chip->typec_port, TYPEC_HOST);
			typec_set_pwr_role(chip->typec_port, TYPEC_SOURCE);
			if (!chip->partner) {
				typec_set_pwr_opmode(chip->typec_port, TYPEC_PWR_MODE_1_5A);
				memset(&chip->partner_identity, 0, sizeof(chip->partner_identity));
				chip->partner_desc.usb_pd = false;
				chip->partner_desc.accessory = TYPEC_ACCESSORY_NONE;
				chip->partner = typec_register_partner(chip->typec_port,
					&chip->partner_desc);
			}
#if 0 /* PEGA: not supported */
			val.intval = POWER_SUPPLY_TYPEC_PR_SOURCE;
			power_supply_set_property(chip->usbpd->usb_psy,
				POWER_SUPPLY_PROP_TYPEC_POWER_ROLE, &val);
#endif
		}
		break;
	case CC_NO_ORIENT:
		// pr_info("FUSB %s:CC_NO_ORIENT=0x%x\n", __func__, event);
		if (chip->usbpd->has_dp) {
			chip->usbpd->has_dp = false;
#if 0 /* PEGA: not supported */
			handler = find_svid_handler(chip->usbpd, 0xFF01);
			if (handler && handler->disconnect) {
				handler->disconnect(handler);
				handler->discovered = true;
				chip->usbpd->ss_lane_svid = 0x0;
			}
#endif

			/* Set to USB only mode when cable disconnected */
			extcon_blocking_sync(chip->extcon, EXTCON_DISP_DP, 0);
		}

		start_power_swap = false;
		if (usb_state == 1) {
			cancel_delayed_work_sync(&chip->pd_delayed_work);
			stop_usb_peripheral(chip);
			usb_state = 0;
			pr_debug("FUSB - %s stop_usb_peripheral,event=0x%x,usb_state=%d\n",
				__func__, event, usb_state);
		} else if (usb_state == 2) {
			stop_usb_host(chip);
			usb_state = 0;
			pr_debug("FUSB - %s stop_usb_host,event=0x%x,usb_state=%d\n",
				__func__, event, usb_state);
		}

#if 0 /* PEGA: not supported */
		val.intval = POWER_SUPPLY_PD_INACTIVE;
		power_supply_set_property(chip->usbpd->usb_psy,
			POWER_SUPPLY_PROP_PD_ACTIVE, &val);

		val.intval = 0;
		power_supply_set_property(chip->usbpd->usb_psy,
			POWER_SUPPLY_PROP_PD_CURRENT_MAX, &val);

		val.intval = 5000000;
		power_supply_set_property(chip->usbpd->usb_psy,
			POWER_SUPPLY_PROP_PD_VOLTAGE_MIN, &val);
		power_supply_set_property(chip->usbpd->usb_psy,
			POWER_SUPPLY_PROP_PD_VOLTAGE_MAX, &val);

		//dual_role_instance_changed(chip->usbpd->dual_role);

		/* Port to default dr pr mode */
		val.intval = POWER_SUPPLY_TYPEC_PR_DUAL;
		power_supply_set_property(chip->usbpd->usb_psy,
			POWER_SUPPLY_PROP_TYPEC_POWER_ROLE, &val);
#endif
		if (extcon_get_state(chip->extcon, EXTCON_CHG_USB_FAST) > 0)
			extcon_set_state(chip->extcon, EXTCON_CHG_USB_FAST, false);

//		if (chip->current_pr != PR_NONE) {
			typec_set_pwr_role(chip->typec_port, TYPEC_SINK);
#if 0 /* PEGA: not supported */
			chip->current_pr = PR_NONE;
#endif

//		}

//		if (chip->current_dr != DR_NONE ) {
			typec_set_data_role(chip->typec_port, TYPEC_DEVICE);
#if 0 /* PEGA: not supported */
			chip->current_dr = DR_NONE;
#endif
//		}
		typec_set_pwr_opmode(chip->typec_port, TYPEC_PWR_MODE_USB);
		typec_unregister_partner(chip->partner);
		chip->partner = NULL;
		chip->port.PortConfig.PortType = USBTypeC_DRP;
		chip->port.PortConfig.SnkPreferred = TRUE;
		chip->port.PortConfig.SrcPreferred = FALSE;
#if 0 /* PEGA: not supported */
		pr_info("FUSB %s:set to default mode,current_pr=%d,current_dr=%d\n",
			__func__, chip->current_pr, chip->current_dr);
#else
		// pr_info("FUSB %s:set to default mode\n", __func__);
#endif

		break;
	case PD_STATE_CHANGED:
		pr_debug("FUSB %s:PD_STATE_CHANGED=0x%x, PE_ST=%d\n",
			__func__, event, chip->port.PolicyState);
		if (chip->port.PolicyState == peSinkReady &&
			chip->port.PolicyHasContract == TRUE) {
#if 0 /* PEGA: not supported */
			pr_info("FUSB %s update power_supply properties\n",
				__func__);

			val.intval = POWER_SUPPLY_PD_ACTIVE;
			power_supply_set_property(chip->usbpd->usb_psy,
				POWER_SUPPLY_PROP_PD_ACTIVE, &val);

			set_voltage = chip->port.SrcCapsReceived[
				chip->port.USBPDContract.FVRDO.ObjectPosition - 1].FPDOSupply.Voltage;
			op_current = chip->port.USBPDContract.FVRDO.OpCurrent;

			if (op_current > 0){
				val.intval = op_current * 10 * 1000;
				power_supply_set_property(chip->usbpd->usb_psy,
					POWER_SUPPLY_PROP_PD_CURRENT_MAX, &val);

				val.intval = 5000000;
				power_supply_set_property(chip->usbpd->usb_psy,
					POWER_SUPPLY_PROP_PD_VOLTAGE_MIN, &val);
				if (set_voltage > 100){
					val.intval = 9000000;
					power_supply_set_property(chip->usbpd->usb_psy,
						POWER_SUPPLY_PROP_PD_VOLTAGE_MAX, &val);
				} else {
					val.intval = 5000000;
					power_supply_set_property(chip->usbpd->usb_psy,
						POWER_SUPPLY_PROP_PD_VOLTAGE_MAX, &val);
				}
			}
#endif
			set_voltage = chip->port.SrcCapsReceived[
				chip->port.USBPDContract.FVRDO.ObjectPosition - 1].FPDOSupply.Voltage * 50;
			op_current = chip->port.USBPDContract.FVRDO.OpCurrent * 10;
			if (op_current > 0) {
				union extcon_property_value property;

				extcon_set_state(chip->extcon, EXTCON_CHG_USB_FAST, true);
				property.intval = (op_current << 15 | set_voltage);
				extcon_set_property(chip->extcon, EXTCON_CHG_USB_FAST,
							EXTCON_PROP_USB_TYPEC_POLARITY,
							property);
				extcon_sync(chip->extcon, EXTCON_CHG_USB_FAST);
				pr_info("PD sink %dmV/%dmA\n", set_voltage, op_current);
			}
		}

		/* set typec port */
		if ((chip->port.PolicyState == peSinkReady ||
			chip->port.PolicyState == peSourceReady) &&
			chip->port.PolicyHasContract == TRUE) {
			typec_set_pwr_opmode(chip->typec_port, TYPEC_PWR_MODE_PD);
		}

		break;
	case PD_NO_CONTRACT:
		pr_debug("FUSB %s:PD_NO_CONTRACT=0x%x, PE_ST=%d\n",
			__func__, event, chip->port.PolicyState);

#if 0 /* PEGA: not supported */
		val.intval = POWER_SUPPLY_PD_INACTIVE;
		power_supply_set_property(chip->usbpd->usb_psy,
			POWER_SUPPLY_PROP_PD_ACTIVE, &val);

		val.intval = 5000000;
		power_supply_set_property(chip->usbpd->usb_psy,
			POWER_SUPPLY_PROP_PD_VOLTAGE_MIN, &val);
		power_supply_set_property(chip->usbpd->usb_psy,
			POWER_SUPPLY_PROP_PD_VOLTAGE_MAX, &val);
#endif
		extcon_set_state(chip->extcon, EXTCON_CHG_USB_FAST, false);
		break;
	case SVID_EVENT:
		chip->usbpd->has_dp = FALSE;
		chip->usbpd->block_dp_event = TRUE;
#if 0 /* PEGA: not supported */
		for (i = 0; i < chip->port.core_svid_info.num_svids; i++)
		{
			handler = find_svid_handler(chip->usbpd, chip->port.core_svid_info.svids[i]);
			if (handler) {
				pr_debug("FUSB %s:Get handler for %4x\n", __func__, chip->port.core_svid_info.svids[i]);
				ret = usbpd_release_ss_lane(chip->usbpd, handler);
				pr_debug("FUSB %s: usbpd_release_ss_lane return ret=%d\n", __func__, ret);

				handler->connect(handler, chip->usbpd->peer_usb_comm);
				handler->discovered = true;
				chip->usbpd->block_dp_event = FALSE;
			}
		}
#endif
		break;
	case DP_EVENT:
		pr_debug("FUSB %s:DP_EVENT=0x%x\n", __func__, event);
		pr_debug("FUSB %s:chip->port.AutoVdmState=%d\n",
			__func__, chip->port.AutoVdmState);

		if (chip->usbpd->has_dp == FALSE) {
			chip->usbpd->has_dp = TRUE;
		}
#if 0 /* PEGA: not supported */
		handler = find_svid_handler(chip->usbpd, 0xFF01);
		if (handler && handler->svdm_received && !chip->usbpd->block_dp_event) {
			arr_in = (FSC_U32*)app_ctx;
			vdmh_in.object = arr_in[0];

			handler->svdm_received(handler, vdmh_in.SVDM.Command,
				vdmh_in.SVDM.CommandType,
				arr_in + 1,
				chip->port.PolicyRxHeader.NumDataObjects - 1);
		}
#endif
		break;
	case DATA_ROLE:
		pr_debug("FUSB %s:DATA_ROLE=0x%x\n", __func__, event);

		if (chip->port.PolicyIsDFP == FALSE) {
			if (usb_state == 2)
				stop_usb_host(chip);
			start_usb_peripheral(chip);
			usb_state = 1;
		} else if (chip->port.PolicyIsDFP == TRUE) {
			if (usb_state == 1)
				stop_usb_peripheral(chip);
			start_usb_host(chip, true);
			usb_state = 2;

			/* ensure host is started before allowing DP */
			//extcon_blocking_sync(chip->extcon, EXTCON_USB_HOST, 0);
		}

		//dual_role_instance_changed(chip->usbpd->dual_role);

		/* set typec port */
		if (chip->port.PolicyIsDFP == TRUE) {
#if 0 /* PEGA: not supported */
			chip->current_dr = DR_DFP;
#endif
			typec_set_data_role(chip->typec_port, TYPEC_HOST);
			pr_err("FUSB - %s-%d: fusb302b PolicyIsDFP=0x%x, set typec_set_data_role", __func__, __LINE__, chip->port.PolicyIsDFP);
		} else {
#if 0 /* PEGA: not supported */
			chip->current_dr = DR_UFP;
#endif
			typec_set_data_role(chip->typec_port, TYPEC_DEVICE);
			pr_err("FUSB - %s-%d: fusb302b PolicyIsDFP=0x%x, set typec_set_data_role", __func__,__LINE__, chip->port.PolicyIsDFP);
		}

		break;
	case POWER_ROLE:
		pr_debug("FUSB - %s:POWER_ROLE=0x%x", __func__, event);
		if (start_power_swap == FALSE) {
			start_power_swap = true;
#if 0 /* PEGA: not supported */
			val.intval = 1;
			power_supply_set_property(chip->usbpd->usb_psy,
				POWER_SUPPLY_PROP_PR_SWAP, &val);
#endif
		} else {
			start_power_swap = false;
#if 0 /* PEGA: not supported */
			val.intval = 0;
			power_supply_set_property(chip->usbpd->usb_psy,
				POWER_SUPPLY_PROP_PR_SWAP, &val);
#endif
		}

		/* set typec port */
		if (chip->port.PolicyIsSource == FALSE) {
#if 0 /* PEGA: not supported */
		 chip->current_pr = PR_SINK;
#endif
		 typec_set_pwr_role(chip->typec_port, TYPEC_SINK);
		 pr_err("FUSB - %s-%d: fusb302b PolicyIsSource=0x%x, set typec_set_pwr_role", __func__, __LINE__, chip->port.PolicyIsSource);

		} else if (chip->port.PolicyIsSource == TRUE) {
#if 0 /* PEGA: not supported */
		 chip->current_pr = PR_SRC;
#endif
		 typec_set_pwr_role(chip->typec_port, TYPEC_SOURCE);
		 pr_err("FUSB - %s-%d: fusb302b PolicyIsSource=0x%x, set typec_set_pwr_role", __func__, __LINE__, chip->port.PolicyIsSource);
		}

		break;
	default:
		pr_debug("FUSB - %s:default=0x%x", __func__, event);
		break;
	}
}

void fusb_init_event_handler(void)
{
	register_observer(CC_ORIENT_ALL|PD_CONTRACT_ALL|POWER_ROLE|
			PD_STATE_CHANGED|DATA_ROLE|EVENT_ALL,
			handle_core_event, NULL);
}
