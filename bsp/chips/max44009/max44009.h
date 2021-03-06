/**
 * \file
 *         Device drivers for MAX44009 light sensor in OpenMote-CC2538.
 * \author
 *         Pere Tuset, OpenMote <peretuset@openmote.com>
 */

#ifndef OPENWSN_MAX44009_H
#define OPENWSN_MAX44009_H

void max44009_init(void);
void max44009_reset(void);
uint8_t max44009_is_present(void);
uint16_t max44009_read_light(void);
float max44009_convert_light(uint16_t light);

#endif /* OPENWSN_MAX44009_H */

