/* 
 * File:   fusb30x_driver.c
 * Company: Fairchild Semiconductor
 *
 * Created on September 2, 2015, 10:22 AM
 */

/* Standard Linux includes */
#include <linux/init.h>                                                         // __init, __initdata, etc
#include <linux/module.h>                                                       // Needed to be a module
#include <linux/kernel.h>                                                       // Needed to be a kernel module
#include <linux/i2c.h>                                                          // I2C functionality
#include <linux/slab.h>                                                         // devm_kzalloc
#include <linux/types.h>                                                        // Kernel datatypes
#include <linux/errno.h>                                                        // EINVAL, ERANGE, etc
#include <linux/of_device.h>                                                    // Device tree functionality
#include <linux/extcon.h>
#include <linux/extcon-provider.h>
#if 0 /* PEGA: not supported */
#include <linux/usb/usbpd.h>
#endif
#include <linux/regulator/consumer.h>
#include <linux/power_supply.h>

/* Driver-specific includes */
#include "fusb30x_global.h"                                                     // Driver-specific structures/types
#include "platform_helpers.h"                                                   // I2C R/W, GPIO, misc, etc
#include "platform_usbpd.h"
#include "../core/core.h"                                                       // GetDeviceTypeCStatus

#ifdef FSC_DEBUG
#include "dfs.h"
#endif // FSC_DEBUG

#include "fusb30x_driver.h"
#include "platform_usbpd.h"

/******************************************************************************
* Driver functions
******************************************************************************/
static int __init fusb30x_init(void)
{
    pr_info("FUSB  %s - Start driver initialization...\n", __func__);

	return i2c_add_driver(&fusb30x_driver);
}

static void __exit fusb30x_exit(void)
{
	i2c_del_driver(&fusb30x_driver);
    pr_debug("FUSB  %s - Driver deleted...\n", __func__);
}

static int fusb302_i2c_resume(struct device* dev)
{
    struct fusb30x_chip *chip;
        struct i2c_client *client = to_i2c_client(dev);

        if (client) {
            chip = i2c_get_clientdata(client);
                if (chip)
                up(&chip->suspend_lock);
        }
     return 0;
}

static int fusb302_i2c_suspend(struct device* dev)
{
    struct fusb30x_chip* chip;
        struct i2c_client* client =  to_i2c_client(dev);

        if (client) {
             chip = i2c_get_clientdata(client);
                 if (chip)
                    down(&chip->suspend_lock);
        }
        return 0;
}

static const unsigned int usbpd_extcon_cable[] = {
	EXTCON_USB,
	EXTCON_USB_HOST,
	EXTCON_USB_VBUS_EN,
	EXTCON_CHG_USB_SDP,
	EXTCON_CHG_USB_CDP,
	EXTCON_CHG_USB_DCP,
	EXTCON_CHG_USB_SLOW,
	EXTCON_CHG_USB_FAST,
	EXTCON_DISP_DP,
	EXTCON_NONE,
};

static void pd_delayed_work_test(struct work_struct *work)
{
#if 0 /* PEGA: not supported */
	int ret = 0;
	union power_supply_propval val = {0};
	struct fusb30x_chip* chip =
			container_of(work, struct fusb30x_chip, pd_delayed_work.work);

	ret = power_supply_get_property(chip->usbpd->usb_psy,
			POWER_SUPPLY_PROP_REAL_TYPE,&val);

	if ( ( ret < 0 || val.intval == POWER_SUPPLY_TYPE_UNKNOWN )
		&& chip->count < chip->count_MAX ) {
		chip->count++;
		schedule_delayed_work(&chip->pd_delayed_work, msecs_to_jiffies(100));
	}
	else
		start_usb_peripheral(chip);
#endif
}

static int fusb30x_probe (struct i2c_client* client,
                          const struct i2c_device_id* id)
{
    int ret = 0;
    struct regulator *vbus;
    struct fusb30x_chip* chip;
    struct i2c_adapter* adapter;
#if 0 /* PEGA: not supported */
	struct power_supply *usb_psy;
#endif

	pr_info("FUSB - %s\n", __func__);

    if (!client) {
        pr_err("FUSB  %s - Error: Client structure is NULL!\n", __func__);
        return -EINVAL;
    }
    dev_info(&client->dev, "%s\n", __func__);

    /* Make sure probe was called on a compatible device */
	if (!of_match_device(fusb30x_dt_match, &client->dev)) {
		dev_err(&client->dev,
			"FUSB  %s - Error: Device tree mismatch!\n",
			__func__);
		return -EINVAL;
	}
    pr_debug("FUSB  %s - Device tree matched!\n", __func__);

#if 0 /* PEGA: not supported */
	/* register power supply */
	usb_psy = power_supply_get_by_name("usb");
	if (!usb_psy) {
		pr_info("FUSB - %s Could not get USB power_supply, deferring probe\n",
			__func__);
		return -EPROBE_DEFER;
	}
#endif

	vbus = devm_regulator_get(&client->dev, "vbus");
	if (IS_ERR(vbus)) {
		dev_err(&client->dev,
			"FUSB  %s - Error: defer probe due to no vbus present\n",
			__func__);
#if 0 /* PEGA: not supported */
		power_supply_put(usb_psy);
#endif
		return -EPROBE_DEFER;
	}

    /* Allocate space for our chip structure (devm_* is managed by the device) */
    chip = devm_kzalloc(&client->dev, sizeof(*chip), GFP_KERNEL);
    if (!chip) {
		dev_err(&client->dev,
			"FUSB  %s - Error: Unable to allocate memory for g_chip!\n",
			__func__);
		devm_regulator_put(vbus); // TODO: handler other error in probe.
#if 0 /* PEGA: not supported */
		power_supply_put(usb_psy);
#endif
		return -ENOMEM;
	}

    chip->client = client;                                                      // Assign our client handle to our chip
    fusb30x_SetChip(chip);                                                      // Set our global chip's address to the newly allocated memory
    pr_debug("FUSB  %s - Chip structure is set! Chip: %p ... g_chip: %p\n", __func__, chip, fusb30x_GetChip());

    /* Initialize the chip lock */
    mutex_init(&chip->lock);

    /* Initialize the chip's data members */
    fusb_InitChipData();
    pr_debug("FUSB  %s - Chip struct data initialized!\n", __func__);

	/* Add QRD extcon */
	chip->extcon = devm_extcon_dev_allocate(&client->dev, usbpd_extcon_cable);
	if (IS_ERR(chip->extcon)) {
		dev_err(&client->dev,
			"FUSB %s - Error: Unable to allocate memory for extcon!\n",
			__func__);
		return PTR_ERR(chip->extcon);
	}
	ret = devm_extcon_dev_register(&client->dev, chip->extcon);
	if (ret) {
		dev_err(&client->dev, "FUSB failed to register extcon device\n");
		return -1;
	}

	chip->usbpd = fusb30x_usbpd_create(&client->dev);
	if (!chip->usbpd) {
		dev_err(&client->dev,
			"FUSB %s - Error: Unable to allocate memory for g_chip!\n",
			__func__);
	}

	extcon_set_property_capability(chip->extcon, EXTCON_USB,
			EXTCON_PROP_USB_TYPEC_POLARITY);
	extcon_set_property_capability(chip->extcon, EXTCON_USB,
			EXTCON_PROP_USB_SS);
	extcon_set_property_capability(chip->extcon, EXTCON_USB,
			EXTCON_PROP_USB_TYPEC_MED_HIGH_CURRENT);
	extcon_set_property_capability(chip->extcon, EXTCON_USB_HOST,
			EXTCON_PROP_USB_TYPEC_POLARITY);
	extcon_set_property_capability(chip->extcon, EXTCON_USB_HOST,
			EXTCON_PROP_USB_SS);
	extcon_set_property_capability(chip->extcon, EXTCON_CHG_USB_FAST,
			EXTCON_PROP_USB_TYPEC_POLARITY);

	chip->is_vbus_present = FALSE;
	chip->vbus = vbus;
#if 0 /* PEGA: not supported */
	chip->usbpd->usb_psy = usb_psy;
#endif
	fusb_init_event_handler();

    /* Verify that the system has our required I2C/SMBUS functionality (see <linux/i2c.h> for definitions) */
    adapter = to_i2c_adapter(client->dev.parent);
    if (i2c_check_functionality(adapter, FUSB30X_I2C_SMBUS_BLOCK_REQUIRED_FUNC))
    {
        chip->use_i2c_blocks = true;
    }
    else
    {
        // If the platform doesn't support block reads, try with block writes and single reads (works with eg. RPi)
        // NOTE: It is likely that this may result in non-standard behavior, but will often be 'close enough' to work for most things
        dev_warn(&client->dev, "FUSB  %s - Warning: I2C/SMBus block read/write functionality not supported, checking single-read mode...\n", __func__);
        if (!i2c_check_functionality(adapter, FUSB30X_I2C_SMBUS_REQUIRED_FUNC))
        {
            dev_err(&client->dev, "FUSB  %s - Error: Required I2C/SMBus functionality not supported!\n", __func__);
            dev_err(&client->dev, "FUSB  %s - I2C Supported Functionality Mask: 0x%x\n", __func__, i2c_get_functionality(adapter));
            return -EIO;
        }
    }
    pr_debug("FUSB  %s - I2C Functionality check passed! Block reads: %s\n", __func__, chip->use_i2c_blocks ? "YES" : "NO");

    /* Assign our struct as the client's driverdata */
    i2c_set_clientdata(client, chip);
    pr_debug("FUSB  %s - I2C client data set!\n", __func__);

    /* Verify that our device exists and that it's what we expect */
    if (!fusb_IsDeviceValid())
    {
        dev_err(&client->dev, "FUSB  %s - Error: Unable to communicate with device!\n", __func__);
        return -EIO;
    }
    pr_debug("FUSB  %s - Device check passed!\n", __func__);

    /* init typec port class */
    chip->typec_caps.type = TYPEC_PORT_DRP;
    chip->typec_caps.data = TYPEC_PORT_DRD;
    chip->typec_caps.revision = REVISION;
    chip->typec_caps.pd_revision = PD_REVISION;
    chip->typec_caps.dr_set = fusbpd_typec_dr_set;
    chip->typec_caps.pr_set = fusbpd_typec_pr_set;
    chip->typec_caps.port_type_set = fusbpd_typec_port_type_set;
    chip->partner_desc.identity = &chip->partner_identity;
    chip->typec_port=typec_register_port(&chip->client->dev,&chip->typec_caps);
#if 0 /* PEGA: not supported */
    chip->current_pr = PR_NONE;
    chip->current_dr = DR_NONE;
#endif

#if 1
    /* reset fusb302*/
    fusb_reset();
#endif /* for fix DP issue */
    /* Initialize semaphore*/
    sema_init(&chip->suspend_lock, 1);

    /* Initialize the platform's GPIO pins and IRQ */
    ret = fusb_InitializeGPIO();
    if (ret)
    {
        dev_err(&client->dev, "FUSB  %s - Error: Unable to initialize GPIO!\n", __func__);
        return ret;
    }
    pr_debug("FUSB  %s - GPIO initialized!\n", __func__);

    /* Initialize sysfs file accessors */
    fusb_Sysfs_Init();
    pr_debug("FUSB  %s - Sysfs nodes created!\n", __func__);

#ifdef FSC_DEBUG
    /* Initialize debugfs file accessors */
    fusb_DFS_Init();
    pr_debug("FUSB  %s - DebugFS nodes created!\n", __func__);
#endif // FSC_DEBUG

#if 1
    /* Enable interrupts after successful core/GPIO initialization */
    ret = fusb_EnableInterrupts();
    if (ret)
    {
        dev_err(&client->dev, "FUSB  %s - Error: Unable to enable interrupts! Error code: %d\n", __func__, ret);
        return -EIO;
    }

    /* Initialize the core and enable the state machine (NOTE: timer and GPIO must be initialized by now)
    *  Interrupt must be enabled before starting 302 initialization */
    fusb_InitializeCore();
    pr_debug("FUSB  %s - Core is initialized!\n", __func__);
#endif /* for fix DP issue*/
    chip->pd_workqueue_struct = create_singlethread_workqueue("pd charger delay");
    INIT_DELAYED_WORK(&chip->pd_delayed_work, pd_delayed_work_test);
    dev_info(&client->dev, "FUSB  %s - FUSB30X Driver loaded successfully!\n", __func__);
	return ret;
}

static int fusb30x_remove(struct i2c_client* client)
{
    pr_debug("FUSB  %s - Removing fusb30x device!\n", __func__);

#ifdef FSC_DEBUG
    /* Remove debugfs file accessors */
    fusb_DFS_Cleanup();
    pr_debug("FUSB  %s - DebugFS nodes removed.\n", __func__);
#endif // FSC_DEBUG

    fusb_GPIO_Cleanup();
    pr_debug("FUSB  %s - FUSB30x device removed from driver...\n", __func__);
    return 0;
}

static void fusb30x_shutdown(struct i2c_client *client)
{
    fusb_reset();
        pr_debug("FUSB	%s - fusb302 shutdown\n", __func__);
}

/*******************************************************************************
 * Driver macros
 ******************************************************************************/
module_init(fusb30x_init);                                                      // Defines the module's entrance function
module_exit(fusb30x_exit);                                                      // Defines the module's exit function

MODULE_LICENSE("GPL");                                                          // Exposed on call to modinfo
MODULE_DESCRIPTION("Fairchild FUSB30x Driver");                                 // Exposed on call to modinfo
MODULE_AUTHOR("Fairchild");                        								// Exposed on call to modinfo
