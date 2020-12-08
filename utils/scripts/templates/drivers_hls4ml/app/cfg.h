#ifndef __ESP_CFG_000_H__
#define __ESP_CFG_000_H__

#include "libesp.h"
#include "<accelerator_name>.h"

typedef /* <<--token-type-->> */ token_t;

/* <<--params-def-->> */

/* <<--params-->> */

#define NACC 1

#define INT_BITS /* <<--int_bits-->> */
#define fl2fx(A) float_to_fixed/* <<--data_width-->> */(A, INT_BITS)

struct <accelerator_name>_access <accelerator_name>_cfg_000[] = {
	{
		/* <<--descriptor-->> */
		.src_offset = 0,
		.dst_offset = 0,
		.esp.coherence = ACC_COH_NONE,
		.esp.p2p_store = 0,
		.esp.p2p_nsrcs = 0,
		.esp.p2p_srcs = {"", "", "", ""},
	}
};

esp_thread_info_t cfg_000[] = {
	{
		.run = true,
		.devname = "<accelerator_name>.0",
		.ioctl_req = <ACCELERATOR_NAME>_IOC_ACCESS,
		.esp_desc = &(<accelerator_name>_cfg_000[0].esp),
	}
};

#endif /* __ESP_CFG_000_H__ */
