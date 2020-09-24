#ifndef TETRA_MLE_H
#define TETRA_MLE_H

int rx_mm_pdu(enum tetra_mm_pdu_type_d type, struct tetra_mac_state *tms, struct msgb *msg, unsigned int len);
int rx_cmce_pdu(enum tetra_cmce_pdu_type_d type, struct tetra_mac_state *tms, struct msgb *msg, unsigned int len);
int rx_mle_pdu(enum tetra_mle_pdu_type_d type, struct tetra_mac_state *tms, struct msgb *msg, unsigned int len);

#endif
