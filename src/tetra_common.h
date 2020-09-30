#ifndef TETRA_COMMON_H
#define TETRA_COMMON_H

#include <stdint.h>
#include "tetra_mac_pdu.h"
#include <osmocom/core/linuxlist.h>

#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifdef DEBUG
#define DEBUGP(x, args...)	printf(x, ## args)
#else
#define DEBUGP(x, args...)	do { } while(0)
#endif

#define TETRA_SYM_PER_TS	255
#define TETRA_BITS_PER_TS	(TETRA_SYM_PER_TS*2)

/* Chapter 22.2.x */
enum tetra_log_chan {
	TETRA_LC_UNKNOWN,
	/* TMA SAP */
	TETRA_LC_SCH_F,
	TETRA_LC_SCH_HD,
	TETRA_LC_SCH_HU,
	TETRA_LC_STCH,
	TETRA_LC_SCH_P8_F,
	TETRA_LC_SCH_P8_HD,
	TETRA_LC_SCH_P8_HU,

	TETRA_LC_AACH,
	TETRA_LC_TCH,
	TETRA_LC_BSCH,
	TETRA_LC_BNCH,

	/* FIXME: QAM */
	TETRA_LC_SCH_Q_RA,
	TETRA_LC_SCH_Q_D25_4H,
	TETRA_LC_SCH_Q_D25_16H,
	TETRA_LC_SCH_Q_D25_16U,
	TETRA_LC_SCH_Q_D25_64H,
	TETRA_LC_SCH_Q_D25_64M,
	TETRA_LC_SCH_Q_D25_64U,
	TETRA_LC_SCH_Q_D50_4H,
	TETRA_LC_SCH_Q_D50_16H,
	TETRA_LC_SCH_Q_D50_16U,
	TETRA_LC_SCH_Q_D50_64H,
	TETRA_LC_SCH_Q_D50_64M,
	TETRA_LC_SCH_Q_D50_64U,
	TETRA_LC_SCH_Q_D100_4H,
	TETRA_LC_SCH_Q_D100_16H,
	TETRA_LC_SCH_Q_D100_16U,
	TETRA_LC_SCH_Q_D100_64H,
	TETRA_LC_SCH_Q_D100_64M,
	TETRA_LC_SCH_Q_D100_64U,
	TETRA_LC_SCH_Q_D150_4H,
	TETRA_LC_SCH_Q_D150_16H,
	TETRA_LC_SCH_Q_D150_16U,
	TETRA_LC_SCH_Q_D150_64H,
	TETRA_LC_SCH_Q_D150_64M,
	TETRA_LC_SCH_Q_D150_64U,
	TETRA_LC_SCH_Q_U25_4H,
	TETRA_LC_SCH_Q_U25_16H,
	TETRA_LC_SCH_Q_U25_16U,
	TETRA_LC_SCH_Q_U25_64H,
	TETRA_LC_SCH_Q_U25_64M,
	TETRA_LC_SCH_Q_U25_64U,
	TETRA_LC_SCH_Q_U50_4H,
	TETRA_LC_SCH_Q_U50_16H,
	TETRA_LC_SCH_Q_U50_16U,
	TETRA_LC_SCH_Q_U50_64H,
	TETRA_LC_SCH_Q_U50_64M,
	TETRA_LC_SCH_Q_U50_64U,
	TETRA_LC_SCH_Q_U100_4H,
	TETRA_LC_SCH_Q_U100_16H,
	TETRA_LC_SCH_Q_U100_16U,
	TETRA_LC_SCH_Q_U100_64H,
	TETRA_LC_SCH_Q_U100_64M,
	TETRA_LC_SCH_Q_U100_64U,
	TETRA_LC_SCH_Q_U150_4H,
	TETRA_LC_SCH_Q_U150_16H,
	TETRA_LC_SCH_Q_U150_16U,
	TETRA_LC_SCH_Q_U150_64H,
	TETRA_LC_SCH_Q_U150_64M,
	TETRA_LC_SCH_Q_U150_64U,
	TETRA_LC_SCH_Q_HU25_4H,
	TETRA_LC_SCH_Q_HU25_16H,
	TETRA_LC_SCH_Q_HU25_16U,
	TETRA_LC_SCH_Q_HU25_64H,
	TETRA_LC_SCH_Q_HU25_64M,
	TETRA_LC_SCH_Q_HU25_64U,
	TETRA_LC_SCH_Q_HU50_4H,
	TETRA_LC_SCH_Q_HU50_16H,
	TETRA_LC_SCH_Q_HU50_16U,
	TETRA_LC_SCH_Q_HU50_64H,
	TETRA_LC_SCH_Q_HU50_64M,
	TETRA_LC_SCH_Q_HU50_64U,
	TETRA_LC_SCH_Q_HU100_4H,
	TETRA_LC_SCH_Q_HU100_16H,
	TETRA_LC_SCH_Q_HU100_16U,
	TETRA_LC_SCH_Q_HU100_64H,
	TETRA_LC_SCH_Q_HU100_64M,
	TETRA_LC_SCH_Q_HU100_64U,
	TETRA_LC_SCH_Q_HU150_4H,
	TETRA_LC_SCH_Q_HU150_16H,
	TETRA_LC_SCH_Q_HU150_16U,
	TETRA_LC_SCH_Q_HU150_64H,
	TETRA_LC_SCH_Q_HU150_64M,
	TETRA_LC_SCH_Q_HU150_64U,

	TETRA_LC_SCH_Q_B50,
	TETRA_LC_SCH_Q_B100,
	TETRA_LC_SCH_Q_B150,

	TETRA_LC_BNCH_Q,
	TETRA_LC_BSCH_Q,
	TETRA_LC_CLCH_Q,
	TETRA_LC_BLCH_Q,
	TETRA_LC_AACH_Q,
	TETRA_LC_SICH_Q_D25,
	TETRA_LC_SICH_Q_D50,
	TETRA_LC_SICH_Q_D100,
	TETRA_LC_SICH_Q_D150,
	TETRA_LC_SICH_Q_U25,
	TETRA_LC_SICH_Q_U50,
	TETRA_LC_SICH_Q_U100,
	TETRA_LC_SICH_Q_U150,
};
uint32_t bits_to_uint(const uint8_t *bits, unsigned int len);


/* tetra hack --sq5bpf */
#define HACK_MAX_TIME 5
#define HACK_LIVE_MAX_TIME 1
#define HACK_NUM_STRUCTS 256
struct tetra_hack_struct {
	uint32_t ssi;
	uint32_t ssi2;
	time_t lastseen;
	int is_encr;
	char curfile[100];
	char comment[100];
	uint16_t callident;
	int seen; // has been seen before
};

struct  tetra_hack_struct tetra_hack_db[HACK_NUM_STRUCTS];


int tetra_hack_live_socket;
struct sockaddr_in tetra_hack_live_sockaddr;
int tetra_hack_socklen;

int tetra_hack_live_idx;
int tetra_hack_live_lastseen;
int tetra_hack_rxid;

uint32_t tetra_hack_dl_freq, tetra_hack_ul_freq;
uint16_t tetra_hack_la;

uint8_t  tetra_hack_freq_band;
uint8_t  tetra_hack_freq_offset;

#define FRAGSLOT_MSGB_SIZE 8192
#define FRAGSLOT_NR_SLOTS 5
struct fragslot {
	int active;
	int fragtimer;	
	struct msgb *msgb;
	int length;
	int fragments;
	int encryption;
};

struct fragslot fragslots[FRAGSLOT_NR_SLOTS]; /* slots are 1-4 but sometimes  slot==0 */


#define N203 6  /* see N.203 in the tetra docs, should be 4 or greater */

int tetra_hack_reassemble_fragments;
int tetra_hack_all_sds_as_text;
int tetra_hack_allow_encrypted;

/* end tetra hack --sq5bpf */

#include "tetra_tdma.h"
struct tetra_phy_state {
	struct tetra_tdma_time time;
};
extern struct tetra_phy_state t_phy_state;

struct tetra_mac_state {
	struct llist_head voice_channels;
	struct {
		int is_traffic;
	} cur_burst;
	struct tetra_si_decoded last_sid;
};

void tetra_mac_state_init(struct tetra_mac_state *tms);

#define TETRA_CRC_OK	0x1d0f

uint32_t tetra_dl_carrier_hz(uint8_t band, uint16_t carrier, uint8_t offset);
uint32_t tetra_ul_carrier_hz(uint8_t band, uint16_t carrier, uint8_t offset,
		uint8_t duplex, uint8_t reverse);

const char *tetra_get_lchan_name(enum tetra_log_chan lchan);
const char *tetra_get_sap_name(uint8_t sap);
#endif
