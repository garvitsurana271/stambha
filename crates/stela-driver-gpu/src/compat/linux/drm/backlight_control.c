// SPDX-License-Identifier: GPL-2.0-only
/* Native DRM panel backlight bridge for Linux's BACKLIGHT_RAW class devices
 * (e.g. amdgpu_bl0 for OLED/eDP DPCD AUX, intel_backlight, nv_backlight). */
#include <linux/backlight.h>
#include <linux/errno.h>
#include <linux/mutex.h>

int stela_linux_backlight_info(u32 *current_out, u32 *max_out);
int stela_linux_backlight_set(u32 level);

int stela_linux_backlight_info(u32 *current_out, u32 *max_out)
{
	struct backlight_device *bd;
	int level;

	if (!current_out || !max_out)
		return -EINVAL;

	bd = backlight_device_get_by_type(BACKLIGHT_RAW);
	if (!bd)
		return -ENODEV;

	mutex_lock(&bd->ops_lock);
	*max_out = (u32)bd->props.max_brightness;
	if (bd->ops && bd->ops->get_brightness) {
		level = bd->ops->get_brightness(bd);
		if (level < 0)
			level = bd->props.brightness;
	} else {
		level = bd->props.brightness;
	}
	mutex_unlock(&bd->ops_lock);

	*current_out = level < 0 ? 0 : (u32)level;
	return 0;
}

int stela_linux_backlight_set(u32 level)
{
	struct backlight_device *bd = backlight_device_get_by_type(BACKLIGHT_RAW);

	if (!bd)
		return -ENODEV;
	if (level > (u32)bd->props.max_brightness)
		level = (u32)bd->props.max_brightness;
	return backlight_device_set_brightness(bd, level);
}
