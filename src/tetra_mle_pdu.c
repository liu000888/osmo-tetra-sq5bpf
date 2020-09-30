/* Implementation of TETRA MLE PDU parsing */

/* (C) 2011 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <unistd.h>
#include <osmocom/core/utils.h>

#include "tetra_mle_pdu.h"

static const struct value_string mle_pdisc_names[] = {
	{ TMLE_PDISC_MM,	"MM" },
	{ TMLE_PDISC_CMCE,	"CMCE" },
	{ TMLE_PDISC_SNDCP,	"SNDCP" },
	{ TMLE_PDISC_MLE,	"MLE" },
	{ TMLE_PDISC_MGMT,	"MGMT" },
	{ TMLE_PDISC_TEST,	"TEST" },
	{ 0, NULL }
};
const char *tetra_get_mle_pdisc_name(uint8_t pdisc)
{
	return get_value_string(mle_pdisc_names, pdisc);
}

static const struct value_string mle_pdut_d_names[] = {
	{ TMLE_PDUT_D_NEW_CELL,		"D-NEW CELL" },
	{ TMLE_PDUT_D_PREPARE_FAIL,	"D-PREPARE FAIL" },
	{ TMLE_PDUT_D_NWRK_BROADCAST,	"D-NWRK BROADCAST" },
	{ TMLE_PDUT_D_NWRK_BROADCAST_EXT, "D-NWRK BROADCAST EXT" },
	{ TMLE_PDUT_D_RESTORE_ACK,	"D-RESTORE ACK" },
	{ TMLE_PDUT_D_RESTORE_FAIL,	"D-RESTORE FAIL" },
	{ TMLE_PDUT_D_CHANNEL_RESPONSE,	"D-CHANNEL RESPONSE" },
	{ 0, NULL }
};
const char *tetra_get_mle_pdut_name(unsigned int pdut, int uplink)
{
	/* FIXME: uplink */
	return get_value_string(mle_pdut_d_names, pdut);
}

static const struct value_string cmce_disconn_cause_names[] = {
	{ 0x00, "Cause not defined or unknown" },
	{ 0x01, "User requested disconnection" },
	{ 0x02, "Called party busy" },
	{ 0x03, "Called party not reachable" },
	{ 0x04, "Called party does not support encryption" },
	{ 0x05, "Congestion in infrastructure" },
	{ 0x06, "Not allowed traffic case" },
	{ 0x07, "Incompatible traffic case" },
	{ 0x08, "Requested service not available" },
	{ 0x09, "Pre-emptive use of resource" },
	{ 0x0a, "Invalid call identifier" },
	{ 0x0b, "Call rejected by the called party" },
	{ 0x0c, "No idle CC entity" },
	{ 0x0d, "Expiry of timer" },
	{ 0x0e, "SwMI requested disconnection" },
	{ 0x0f, "Acknowledged service not completed" },
	{ 0x10, "Unknown TETRA identity" },
	{ 0x11, "SS-specific disconnection" },
	{ 0x12, "Unknown external subscriber identity" },
	{ 0x13, "Call restoration of the other user failed" },
	{ 0x14, "Called party requires encryption"},
	{ 0x15, "Concurrent set-up not supported"},
	{ 0x16, "Called party is under the same DM-GATE of the calling party"},
	{ 0x17, "Non-call owner requested disconnection"},
};

const char * tetra_get_cmce_pdut_disconnect_cause(uint8_t cause)
{
	return get_value_string(cmce_disconn_cause_names, cause);
}
