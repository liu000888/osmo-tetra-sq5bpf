#ifndef TETRA_BURST_H
#define TETRA_BURST_H

#include <stdint.h>

enum tp_sap_data_type {
	TPSAP_T_SB1,    /* synchonization block 1 */
	TPSAP_T_SB2,    /* synchonization block 2 */
	TPSAP_T_NDB,    /* Normal block */
	TPSAP_T_BBK,    /* Broadcast block */
	TPSAP_T_SCH_HU, /* Half size Uplink Signalling channel */
	TPSAP_T_SCH_F,  /* Full size Signalling channel */
};

extern void tp_sap_udata_ind(enum tp_sap_data_type type, const uint8_t *bits, unsigned int len, void *priv);

/* 9.4.4.2.6 Synchronization continuous downlink burst */
int build_sync_c_d_burst(uint8_t *buf, const uint8_t *sb, const uint8_t *bb, const uint8_t *bkn);

/* 9.4.4.2.5 Normal continuous downlink burst */
int build_norm_c_d_burst(uint8_t *buf, const uint8_t *bkn1, const uint8_t *bb, const uint8_t *bkn2, int two_log_chan);

enum tetra_train_seq {
	TETRA_TRAIN_NORM_1,    /* TCH, SCH/F */
	TETRA_TRAIN_NORM_2,    /* STCH+TCH, STCH+STCH, SCH/HD+SCH/HD, SCH/HD+BNCH */
	TETRA_TRAIN_NORM_3,
	TETRA_TRAIN_SYNC,
	TETRA_TRAIN_EXT,
};

/* find a TETRA training sequence in the burst buffer indicated */
int tetra_find_train_seq(const uint8_t *in, unsigned int end_of_in,
			 uint32_t mask_of_train_seq, unsigned int *offset);

#endif /* TETRA_BURST_H */
