/* Tetra MLE layer  */


/* (C) 2020 Liu <liu000888@hotmail.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>

#include "tetra_common.h"
#include "tetra_prim.h"
#include "tetra_upper_mac.h"
#include "tetra_mac_pdu.h"
#include "tetra_llc_pdu.h"
#include "tetra_mm_pdu.h"
#include "tetra_cmce_pdu.h"
#include "tetra_sndcp_pdu.h"
#include "tetra_mle_pdu.h"
#include "tetra_gsmtap.h"
#include "tetra_sds.h"

static unsigned int seek_off = 0;

static uint32_t bit_seek(uint8_t * bits, unsigned int len)
{
	uint32_t value = bits_to_uint(bits + seek_off, len);
	seek_off += len;
	return value;
}

static void bit_rewind()
{
	seek_off = 0;
}

/* 14.7.1.4 sq5bpf */
int parse_d_connect(struct tetra_mac_state *tms, struct msgb *msg, unsigned int len) {
	uint8_t *bits = msg->l3h+3;
	int n=0;
	int m=0;
	char *nis;
	int tmpdu_offset;
	struct tetra_resrc_decoded rsd;
	char buf[1024];
	char buf2[128];

	memset(&rsd, 0, sizeof(rsd));
	tmpdu_offset = macpdu_decode_resource(&rsd, msg->l1h);
	/* 14.7.1.4 */
	m=5; uint8_t pdu_type=bits_to_uint(bits+n, m); n=n+m;
	m=14; uint16_t callident=bits_to_uint(bits+n, m); n=n+m;
	m=4; uint8_t call_timeout=bits_to_uint(bits+n, m); n=n+m;
	m=1; uint8_t hook_method_sel=bits_to_uint(bits+n, m); n=n+m;
	m=1; uint8_t duplex_sel=bits_to_uint(bits+n, m); n=n+m;
	m=2; uint8_t tx_grant=bits_to_uint(bits+n, m); n=n+m;
	m=1; uint8_t tx_req_permission=bits_to_uint(bits+n, m); n=n+m;
	m=1; uint8_t call_ownership=bits_to_uint(bits+n, m); n=n+m;
	m=1; uint8_t o_bit=bits_to_uint(bits+n, m); n=n+m;
	printf("\nCall Identifier:%i Call timeout:%i hook_method:%i Duplex:%i TX_Grant:%i TX_Request_permission:%i Call ownership:%i\n",callident,call_timeout,hook_method_sel,duplex_sel,tx_grant,tx_req_permission,call_ownership);
	sprintf(buf,"TETMON_begin FUNC:DCONNECTDEC SSI:%i IDX:%i CID:%i CALLOWN:%i",rsd.addr.ssi,rsd.addr.usage_marker,callident,call_ownership);
	if (o_bit) {

		m=1; uint8_t pbit_callpri=bits_to_uint(bits+n, m); n=n+m;
		if (pbit_callpri) {
			m=4; uint8_t callpri=bits_to_uint(bits+n, m); n=n+m;
			printf("Call priority:%i ",callpri);
		}

		m=1; uint8_t pbit_bsi=bits_to_uint(bits+n, m); n=n+m;
		if (pbit_bsi) {
			m=8; uint8_t basic_service_information=bits_to_uint(bits+n, m); n=n+m;
			printf("Basic service information:%i ", basic_service_information);
		}

		m=1; uint8_t pbit_tmpaddr=bits_to_uint(bits+n, m); n=n+m;
		if (pbit_tmpaddr) {
			m=24; uint32_t temp_addr=bits_to_uint(bits+n, m); n=n+m;
			printf("Temp address:%i ",temp_addr);
			sprintf(buf2," SSI2:%i",temp_addr);
			strcat(buf,buf2);
		}

		m=1; uint8_t pbit_nid=bits_to_uint(bits+n, m); n=n+m;
		if (pbit_nid) {
			m=6; uint8_t notifindic=bits_to_uint(bits+n, m); n=n+m;
			nis=(notifindic<28)?notification_indicator_strings[notifindic]:"Reserved";
			printf("Notification indicator:%i [%s] ",notifindic,nis);
			sprintf(buf2," NID:%i [%s]",notifindic,nis);
			strcat(buf,buf2);

		}
		printf("\n");
	}
	sprintf(buf2," RX:%i TETMON_end\r\n",tetra_hack_rxid);
	strcat(buf,buf2);
	sendto(tetra_hack_live_socket, (char *)&buf, strlen(buf) + 1, 0, (struct sockaddr *)&tetra_hack_live_sockaddr, tetra_hack_socklen);
	return 0;
}

/* 14.7.1.5 */
int parse_d_connect_ack(struct tetra_mac_state *tms, struct msgb *msg, unsigned int len)
{
	struct tetra_resrc_decoded rsd;
	memset(&rsd, 0, sizeof(rsd));
	int tmpdu_offset = macpdu_decode_resource(&rsd, msg->l1h);

	uint8_t * bits = msg->l3h + 3;

	char buf[1024];
	char buf2[128];

	bit_rewind();
	uint8_t pdu_type = bit_seek(bits, 5);
	uint16_t call_ident = bit_seek(bits, 14);
	uint8_t call_timeout = bit_seek(bits, 4);
	uint8_t tx_grant = bit_seek(bits, 2);
	uint8_t tx_perm = bit_seek(bits, 1);
	uint8_t o_bit = bit_seek(bits, 1);

	sprintf(buf, "TETMON_begin FUNC:DCONNECTACKDEC SSI:%i IDX:%i CID:%i TXGRANT:%i TXPERM:%i ",
			rsd.addr.ssi,
			rsd.addr.usage_marker,
			call_ident,
			tx_grant,
			tx_perm);

	if (o_bit) {
		uint8_t p_notific_indic = bit_seek(bits, 1);
		if (p_notific_indic) {
			// SS
			uint8_t notific_indic = bit_seek(bits, 6);
			const char * nis = (notific_indic < 28) ? notification_indicator_strings[notific_indic] : "Reserved";
			sprintf(buf2, "NID:%i [%s] ", notific_indic, nis);
			strcat(buf, buf2);
		}
	}
	sprintf(buf2,"RX:%i TETMON_end\r\n",tetra_hack_rxid);
	strcat(buf,buf2);
	sendto(tetra_hack_live_socket, (char *)&buf, strlen((char *)&buf)+1, 0, (struct sockaddr *)&tetra_hack_live_sockaddr, tetra_hack_socklen);

	return 0;
}

/* 14.7.1.6 */
int parse_d_disconnect(struct tetra_mac_state * tms, struct msgb * msg, unsigned int len)
{
	struct tetra_resrc_decoded rsd;
	memset(&rsd, 0, sizeof(rsd));
	int tmpdu_offset = macpdu_decode_resource(&rsd, msg->l1h);

	uint8_t * bits = msg->l3h + 3;

	char buf[1024];
	char buf2[128];

	bit_rewind();
	uint8_t pdu_type = bit_seek(bits, 5);
	uint16_t call_ident = bit_seek(bits, 14);
	uint8_t disconn_cause = bit_seek(bits, 5);

	const char * text_disconn_cause = tetra_get_cmce_pdut_disconnect_cause(disconn_cause);

	sprintf(buf, "TETMON_begin FUNC:DDISCONNECTDEC SSI:%i IDX:%i CID:%i CAUSE:%i [%s]",
				rsd.addr.ssi,
				rsd.addr.usage_marker,
				call_ident,
				disconn_cause,
				text_disconn_cause);

	uint8_t o_bit = bit_seek(bits, 1);
	if (o_bit) {
		uint8_t p_notific_indic = bit_seek(bits, 1);
		if (p_notific_indic) {
			// SS
			uint8_t notific_indic = bit_seek(bits, 6);
			const char * nis = (notific_indic < 28) ? notification_indicator_strings[notific_indic] : "Reserved";
			sprintf(buf2, "NID:%i [%s] ", notific_indic, nis);
			strcat(buf, buf2);
		}
	}

	sprintf(buf2," RX:%i TETMON_end\r\n",tetra_hack_rxid);
	strcat(buf,buf2);
	sendto(tetra_hack_live_socket, (char *)&buf, strlen((char *)&buf)+1, 0, (struct sockaddr *)&tetra_hack_live_sockaddr, tetra_hack_socklen);
	return 0;
}

/* 14.7.1.8 */
int parse_d_info(struct tetra_mac_state * tms, struct msgb * msg, unsigned int len)
{
	struct tetra_resrc_decoded rsd;
	memset(&rsd, 0, sizeof(rsd));
	int tmpdu_offset = macpdu_decode_resource(&rsd, msg->l1h);

	uint8_t * bits = msg->l3h + 3;

	char buf[1024];
	char buf2[128];

	bit_rewind();
	uint8_t 	pdu_type 					= bit_seek(bits, 5);
	uint16_t 	call_ident 					= bit_seek(bits, 14);
	uint8_t 	reset_call_timer 			= bit_seek(bits, 1);
	uint8_t 	poll_req 					= bit_seek(bits, 1);
	uint8_t 	o_bit 						= bit_seek(bits, 1);

	sprintf(buf, "TETMON_begin FUNC:DCONNECTACKDEC SSI:%i IDX:%i CID:%i",
			rsd.addr.ssi,
			rsd.addr.usage_marker,
			call_ident
			);

	if (o_bit) {
		if (bit_seek(bits, 1)) {
			uint16_t new_call_ident 		= bit_seek(bits, 14);
			sprintf(buf2, "NCID:%i ", new_call_ident);
			strcat(buf, buf2);
		}
		if (bit_seek(bits, 1)) {
			uint8_t 	call_timeout 		= bit_seek(bits, 4);
		}
		if (bit_seek(bits, 1)) {
			uint8_t 	call_tout_setup_phase 	= bit_seek(bits, 3);
		}
		if (bit_seek(bits, 1)) {
			uint8_t 	call_ownership 		= bit_seek(bits, 1);
			sprintf(buf2, "CALLOWN:%i ", call_ownership);
			strcat(buf, buf2);
		}
		if (bit_seek(bits, 1)) {
			uint16_t 	modify 				= bit_seek(bits, 9);
		}
		if (bit_seek(bits, 1)) {
			uint8_t 	call_status 		= bit_seek(bits, 3);
			sprintf(buf2, "CALLSTATUS:%i ", call_status);
			strcat(buf, buf2);
		}
		if (bit_seek(bits, 1)) {
			uint32_t 	temp_addr 			= bit_seek(bits, 24);
		}
		if (bit_seek(bits, 1)) {
			uint8_t notific_indic 			= bit_seek(bits, 6);
			const char * nis = (notific_indic < 28) ? notification_indicator_strings[notific_indic] : "Reserved";
			sprintf(buf2, "NID:%i [%s] ", notific_indic, nis);
			strcat(buf, buf2);
		}
		if (bit_seek(bits, 1)) {
			uint8_t poll_resp_percent		= bit_seek(bits, 6);
		}
		if (bit_seek(bits, 1)) {
			uint8_t poll_resp_num 			= bit_seek(bits, 6);
		}
	}
	sprintf(buf2," RX:%i TETMON_end\r\n",tetra_hack_rxid);
	strcat(buf,buf2);
	sendto(tetra_hack_live_socket, (char *)&buf, strlen((char *)&buf)+1, 0, (struct sockaddr *)&tetra_hack_live_sockaddr, tetra_hack_socklen);
	return 0;
}

/* 14.7.1.9 sq5bpf */
int parse_d_release(struct tetra_mac_state *tms, struct msgb *msg, unsigned int len)
{
	uint8_t *bits = msg->l3h+3;
	int n=0;
	int m=0;
	char tmpstr2[1024];
	char *nis;
	int tmpdu_offset;
	struct tetra_resrc_decoded rsd;

	memset(&rsd, 0, sizeof(rsd));
	tmpdu_offset = macpdu_decode_resource(&rsd, msg->l1h);
	/* 14.7.1.9 */
	m=5; uint8_t pdu_type=bits_to_uint(bits+n, m); n=n+m;
	m=14; uint16_t callident=bits_to_uint(bits+n, m); n=n+m;
	m=5; uint16_t disccause=bits_to_uint(bits+n, m); n=n+m;
	m=6; uint16_t notifindic=bits_to_uint(bits+n, m); n=n+m;
	nis=(notifindic<28)?notification_indicator_strings[notifindic]:"Reserved";
	printf("\nCall identifier:%i Disconnect cause:%i NotificationID:%i (%s)\n",callident,disccause,notifindic,nis);
	sprintf(tmpstr2,"TETMON_begin FUNC:DRELEASEDEC SSI:%i CID:%i NID:%i [%s] RX:%i TETMON_end\r\n",rsd.addr.ssi,callident, notifindic,nis,tetra_hack_rxid);
	sendto(tetra_hack_live_socket, (char *)&tmpstr2, strlen((char *)&tmpstr2)+1, 0, (struct sockaddr *)&tetra_hack_live_sockaddr, tetra_hack_socklen);
	return 0;
}

/* 14.7.1.11 sq5bpf */
int parse_d_status(struct tetra_mac_state *tms, struct msgb *msg, unsigned int len)
{
	uint8_t *bits = msg->l3h+3;
	int n=0;
	int m=0;
	char tmpstr2[1024];
	char *nis;
	int tmpdu_offset;
	struct tetra_resrc_decoded rsd;

	memset(&rsd, 0, sizeof(rsd));
	tmpdu_offset = macpdu_decode_resource(&rsd, msg->l1h);
	/* 14.7.1.11 */
	m=5; uint8_t pdu_type=bits_to_uint(bits+n, m); n=n+m;
	uint8_t cpti;
	uint32_t callingssi;
	uint32_t callingext=0;
	m=2;  cpti=bits_to_uint(bits+n, m); n=n+m;
	switch(cpti)
	{
		case 0: /* SNA */
			m=8; callingssi=bits_to_uint(bits+n, m); n=n+m;
			break;
		case 1: /* SSI */
			m=24; callingssi=bits_to_uint(bits+n, m); n=n+m;
			break;
		case 2: /* TETRA Subscriber Identity (TSI) */
			m=24; callingssi=bits_to_uint(bits+n, m); n=n+m;
			m=24; callingext=bits_to_uint(bits+n, m); n=n+m;
			break;
		case 3: /* reserved ? */
			break;
	}

	m=16; uint16_t precoded_status=bits_to_uint(bits+n, m); n=n+m;

	m=1; uint8_t o_bit=bits_to_uint(bits+n, m); n=n+m;

	if (o_bit) {
		/* TODO: parse optional data */
	}
	printf("\nCPTI:%i CalledSSI:%i CallingSSI:%i CallingEXT:%i Status:%i (0x%4.4x)\n",cpti,rsd.addr.ssi,callingssi,callingext,precoded_status);
	sprintf(tmpstr2,"TETMON_begin FUNC:DSTATUSDEC SSI:%i SSI2:%i STATUS:%i RX:%i TETMON_end\r\n",rsd.addr.ssi,callingssi,precoded_status,tetra_hack_rxid);
	sendto(tetra_hack_live_socket, (char *)&tmpstr2, strlen((char *)&tmpstr2)+1, 0, (struct sockaddr *)&tetra_hack_live_sockaddr, tetra_hack_socklen);
	return 0;
}

/* 14.7.1.12 sq5bpf */
int parse_d_setup(struct tetra_mac_state *tms, struct msgb *msg, unsigned int len)
{
	uint8_t *bits = msg->l3h+3;
	int n=0;
	int m=0;
	uint32_t callingssi=0;
	uint32_t callingext=0;
	char tmpstr2[1024];
	struct tetra_resrc_decoded rsd;
	int tmpdu_offset;
	uint16_t notifindic=0;
	uint32_t tempaddr=0;
	uint16_t cpti=0;

	memset(&rsd, 0, sizeof(rsd));
	tmpdu_offset = macpdu_decode_resource(&rsd, msg->l1h);



	/* 14.7.1.12, descriptions on 14.8 */
	m=5; uint8_t pdu_type=bits_to_uint(bits+n, m); n=n+m;
	m=14; uint16_t callident=bits_to_uint(bits+n, m); n=n+m;
	m=4; uint16_t calltimeout=bits_to_uint(bits+n, m);  n=n+m;
	m=1; uint16_t hookmethod=bits_to_uint(bits+n, m); n=n+m;
	m=1; uint16_t duplex=bits_to_uint(bits+n, m); n=n+m;
	m=8; uint8_t basicinfo=bits_to_uint(bits+n, m); n=n+m;
	m=2; uint16_t txgrant=bits_to_uint(bits+n, m); n=n+m;
	m=1; uint16_t txperm=bits_to_uint(bits+n, m); n=n+m;
	m=4; uint16_t callprio=bits_to_uint(bits+n, m); n=n+m;
	m=1; uint8_t obit=bits_to_uint(bits+n, m); n=n+m;
	if (obit)
	{
		m=1; uint8_t pbit_notifindic=bits_to_uint(bits+n, m); n=n+m;
		if (pbit_notifindic) {
			m=6;  notifindic=bits_to_uint(bits+n, m); n=n+m;
		}
		m=1; uint8_t pbit_tempaddr=bits_to_uint(bits+n, m); n=n+m;
		if (pbit_tempaddr) {
			m=24;  tempaddr=bits_to_uint(bits+n, m); n=n+m;
		}
		m=1; uint8_t pbit_cpti=bits_to_uint(bits+n, m); n=n+m;
		if (pbit_cpti) {
			m=2;  cpti=bits_to_uint(bits+n, m); n=n+m;
			switch(cpti)
			{
				case 0: /* SNA */
					m=8; callingssi=bits_to_uint(bits+n, m); n=n+m;
					break;
				case 1: /* SSI */
					m=24; callingssi=bits_to_uint(bits+n, m); n=n+m;
					break;
				case 2: /* TETRA Subscriber Identity (TSI) */
					m=24; callingssi=bits_to_uint(bits+n, m); n=n+m;
					m=24; callingext=bits_to_uint(bits+n, m); n=n+m;
					break;
				case 3: /* reserved ? */
					break;
			}
		}

	}
	printf ("\nCall identifier:%i  Call timeout:%i  Hookmethod:%i  Duplex:%i\n",callident,calltimeout,hookmethod,duplex);
	printf("Basicinfo:0x%2.2X  Txgrant:%i  TXperm:%i  Callprio:%i\n",basicinfo,txgrant,txperm,callprio);
	printf("NotificationID:%i  Tempaddr:%i CPTI:%i  CallingSSI:%i  CallingExt:%i\n",notifindic,tempaddr,cpti,callingssi,callingext);

	sprintf(tmpstr2,"TETMON_begin FUNC:DSETUPDEC IDX:%i SSI:%i SSI2:%i CID:%i NID:%i RX:%i TETMON_end\r\n",
			rsd.addr.usage_marker,
			rsd.addr.ssi,
			callingssi,
			callident,
			notifindic,
			tetra_hack_rxid);
	sendto(tetra_hack_live_socket, (char *)&tmpstr2, strlen(tmpstr2) + 1, 0, (struct sockaddr *)&tetra_hack_live_sockaddr, tetra_hack_socklen);
	return 0;
}

/* 14.7.1.13 */
int parse_d_txceased(struct tetra_mac_state *tms, struct msgb *msg, unsigned int len)
{
	struct tetra_resrc_decoded rsd;
	memset(&rsd, 0, sizeof(rsd));
	int tmpdu_offset = macpdu_decode_resource(&rsd, msg->l1h);

	uint8_t * bits = msg->l3h + 3;

	char buf[1024];
	char buf2[128];

	bit_rewind();
	uint8_t 	pdu_type 		= bit_seek(bits, 5);
	uint16_t 	call_ident 		= bit_seek(bits, 14);
	uint8_t 	tx_req_perm		= bit_seek(bits, 1);
	uint8_t 	o_bit 			= bit_seek(bits, 1);
	sprintf(buf, "TETMON_begin FUNC:DTXCEASEDDEC SSI:%i IDX:%i CID:%i TXPERM:%i ",
				rsd.addr.ssi,
				rsd.addr.usage_marker,
				call_ident,
				tx_req_perm);

	if (o_bit) {
		if (bit_seek(bits, 1)) {
			uint8_t notific_indic = bit_seek(bits, 6);
			const char * nis = (notific_indic < 28) ? notification_indicator_strings[notific_indic] : "Reserved";
			sprintf(buf2, "NID:%i [%s] ", notific_indic, nis);
			strcat(buf, buf2);
		}
	}

	sprintf(buf2," RX:%i TETMON_end\r\n",tetra_hack_rxid);
	strcat(buf,buf2);
	sendto(tetra_hack_live_socket, (char *)&buf, strlen((char *)&buf)+1, 0, (struct sockaddr *)&tetra_hack_live_sockaddr, tetra_hack_socklen);
	return 0;
}

/* 14.7.1.15 sq5bpf */
int parse_d_txgranted(struct tetra_mac_state *tms, struct msgb *msg, unsigned int len) {
	uint8_t *bits = msg->l3h+3;
	int n=0;
	int m=0;
	char *nis;
	int tmpdu_offset;
	struct tetra_resrc_decoded rsd;
	char buf[1024];
	char buf2[128];

	memset(&rsd, 0, sizeof(rsd));
	tmpdu_offset = macpdu_decode_resource(&rsd, msg->l1h);
	/* 14.7.1.15 */
	m=5; uint8_t pdu_type=bits_to_uint(bits+n, m); n=n+m;
	m=14; uint16_t callident=bits_to_uint(bits+n, m); n=n+m;
	m=2; uint8_t tx_grant=bits_to_uint(bits+n, m); n=n+m;
	m=1; uint8_t tx_req_permission=bits_to_uint(bits+n, m); n=n+m;
	m=1; uint8_t enc_control=bits_to_uint(bits+n, m); n=n+m;
	m=1; uint8_t reserved=bits_to_uint(bits+n, m); n=n+m;
	m=1; uint8_t o_bit=bits_to_uint(bits+n, m); n=n+m;
	printf("\nCall Identifier:%i TX_Grant:%i TX_Request_permission:%i Encryption control:%i\n",callident,tx_grant,tx_req_permission,enc_control);
	sprintf(buf,"TETMON_begin FUNC:DTXGRANTDEC SSI:%i IDX:%i CID:%i TXGRANT:%i TXPERM:%i ENCC:%i",rsd.addr.ssi,rsd.addr.usage_marker,callident,tx_grant,tx_req_permission,enc_control);
	if (o_bit) {
		m=1; uint8_t pbit_nid=bits_to_uint(bits+n, m); n=n+m;
		if (pbit_nid) {
			m=6; uint8_t notifindic=bits_to_uint(bits+n, m); n=n+m;
			nis=(notifindic<28)?notification_indicator_strings[notifindic]:"Reserved";
			printf("Notification indicator:%i [%s] ",notifindic,nis);
			sprintf(buf2," NID:%i [%s]",notifindic,nis);
			strcat(buf,buf2);

		}
		m=1; uint8_t pbit_tpti=bits_to_uint(bits+n, m); n=n+m;
		if (pbit_tpti) {
			m=2; uint8_t tpti=bits_to_uint(bits+n, m); n=n+m;
			uint32_t txssi;
			uint32_t txssiext;

			sprintf(buf2," TPTI:%i",tpti);
			strcat(buf,buf2);

			switch(tpti)
			{
				case 0: /* SNA , this isn't defined for D-TX GRANTED */
					m=8; txssi=bits_to_uint(bits+n, m); n=n+m;
					sprintf(buf2," SSI2:%i",txssi);
					strcat(buf,buf2);

					break;
				case 1: /* SSI */
					m=24; txssi=bits_to_uint(bits+n, m); n=n+m;
					sprintf(buf2," SSI2:%i",txssi);
					strcat(buf,buf2);
					break;
				case 2: /* TETRA Subscriber Identity (TSI) */
					m=24; txssi=bits_to_uint(bits+n, m); n=n+m;
					m=24; txssiext=bits_to_uint(bits+n, m); n=n+m;
					sprintf(buf2," SSI2:%i SSIEXT:%i",txssi,txssiext);
					strcat(buf,buf2);
					break;
				case 3: /* reserved ? */
					break;
			}


		}
		/* TODO: type 3/4 elements */
		printf("\n");
	}
	sprintf(buf2," RX:%i TETMON_end\r\n",tetra_hack_rxid);
	strcat(buf,buf2);
	sendto(tetra_hack_live_socket, (char *)&buf, strlen((char *)&buf)+1, 0, (struct sockaddr *)&tetra_hack_live_sockaddr, tetra_hack_socklen);
	return 0;
}

/* 14.7.1.16 */
int parse_d_txinterrupt(struct tetra_mac_state * tms, struct msgb * msg, unsigned int len)
{
	struct tetra_resrc_decoded rsd;
	memset(&rsd, 0, sizeof(rsd));
	int tmpdu_offset = macpdu_decode_resource(&rsd, msg->l1h);

	uint8_t * bits = msg->l3h + 3;

	char buf[1024];
	char buf2[128];

	bit_rewind();
	uint8_t 	pdu_type 		= bit_seek(bits, 5);
	uint16_t 	call_ident 		= bit_seek(bits, 14);
	uint8_t 	tx_grant 		= bit_seek(bits, 2);
	uint8_t 	tx_req_perm		= bit_seek(bits, 1);
	uint8_t 	encc 			= bit_seek(bits, 1);
	uint8_t 	rsvd 			= bit_seek(bits, 1);
	uint8_t 	o_bit 			= bit_seek(bits, 1);
	if (o_bit) {
		if (bit_seek(bits, 1)) {
			uint8_t notific_indic = bit_seek(bits, 6);
			const char * nis = (notific_indic < 28) ? notification_indicator_strings[notific_indic] : "Reserved";
			sprintf(buf2, "NID:%i [%s] ", notific_indic, nis);
			strcat(buf, buf2);
		}
		if (bit_seek(bits, 1)) {
			uint8_t cpti 		= bit_seek(bits, 6);
			uint32_t callingssi, callingext;
			switch (cpti) {
			case 1:
				callingssi = bit_seek(bits, 24);
				break;
			case 2:
				callingssi = bit_seek(bits, 24);
				callingext = bit_seek(bits, 24);
				break;
			default:
				break;
			}
		}
	}
	uint8_t 	m_bit 			= bit_seek(bits, 1);

	return 0;
}

/* 14.7.1.17 */
int parse_d_txwait(struct tetra_mac_state *tms, struct msgb *msg, unsigned int len)
{
	struct tetra_resrc_decoded rsd;
	memset(&rsd, 0, sizeof(rsd));
	int tmpdu_offset = macpdu_decode_resource(&rsd, msg->l1h);

	uint8_t * bits = msg->l3h + 3;

	char buf[1024];
	char buf2[128];

	bit_rewind();
	uint8_t 	pdu_type 		= bit_seek(bits, 5);
	uint16_t 	call_ident 		= bit_seek(bits, 14);
	uint8_t 	tx_req_perm		= bit_seek(bits, 1);
	uint8_t 	o_bit 			= bit_seek(bits, 1);
	sprintf(buf, "TETMON_begin FUNC:DTXWAITDEC SSI:%i IDX:%i CID:%i TXPERM:%i ",
				rsd.addr.ssi,
				rsd.addr.usage_marker,
				call_ident,
				tx_req_perm);

	if (o_bit) {
		if (bit_seek(bits, 1)) {
			uint8_t notific_indic = bit_seek(bits, 6);
			const char * nis = (notific_indic < 28) ? notification_indicator_strings[notific_indic] : "Reserved";
			sprintf(buf2, "NID:%i [%s] ", notific_indic, nis);
			strcat(buf, buf2);
		}
	}

	sprintf(buf2," RX:%i TETMON_end\r\n",tetra_hack_rxid);
	strcat(buf,buf2);
	sendto(tetra_hack_live_socket, (char *)&buf, strlen((char *)&buf)+1, 0, (struct sockaddr *)&tetra_hack_live_sockaddr, tetra_hack_socklen);
	return 0;
}

/* decode 18.5.17 Neighbour cell information for CA, example in E2.2, table E.18 */
int parse_nci_ca( uint8_t *bits)
{
	int n,m;
	char buf[1024];
	char buf2[128];
	char freqinfo[128];
	n=0;
	m=5; uint8_t cell_id=bits_to_uint(bits+n, m); n=n+m;
	m=2; uint8_t cell_reselection=bits_to_uint(bits+n, m); n=n+m;
	m=1; uint8_t neig_cell_synced=bits_to_uint(bits+n, m); n=n+m;
	m=2; uint8_t cell_load=bits_to_uint(bits+n, m); n=n+m;
	m=12; uint16_t main_carrier_num=bits_to_uint(bits+n, m); n=n+m;
	/* the band and offset info is from the sysinfo message, not sure if this is correct */
	sprintf(buf," NCI:[cell_id:%i cell_resel:%i neigh_synced:%i cell_load:%i carrier:%i %iHz",cell_id,cell_reselection,neig_cell_synced,cell_load,main_carrier_num,tetra_dl_carrier_hz(tetra_hack_freq_band, main_carrier_num, tetra_hack_freq_offset));

	sprintf(freqinfo,"TETMON_begin FUNC:FREQINFO1 DLF:%i",tetra_dl_carrier_hz(tetra_hack_freq_band, main_carrier_num, tetra_hack_freq_offset));

	m=1; uint8_t obit=bits_to_uint(bits+n, m); n=n+m;
	if (obit) {
		m=1; uint8_t pbit_main_carrier_num_ext=bits_to_uint(bits+n, m); n=n+m;
		if (pbit_main_carrier_num_ext) {
			m=4; uint8_t freq_band=bits_to_uint(bits+n, m); n=n+m;
			m=2; uint8_t freq_offset=bits_to_uint(bits+n, m); n=n+m;
			m=3; uint8_t duplex_spacing=bits_to_uint(bits+n, m); n=n+m;
			m=1; uint8_t reverse=bits_to_uint(bits+n, m); n=n+m;
			uint32_t dlfext=tetra_dl_carrier_hz(freq_band, main_carrier_num, freq_offset);
			uint32_t ulfext=tetra_ul_carrier_hz(freq_band, main_carrier_num, freq_offset,duplex_spacing,reverse);

			sprintf(buf2," band:%i offset:%i freq:%iHz uplink:%iHz (duplex:%i rev:%i)",freq_band,freq_offset,dlfext,ulfext,duplex_spacing,reverse);
			strcat(buf,buf2);
			sprintf(buf2,"TETMON_begin FUNC:FREQINFO1 DLF:%i ULF:%i",dlfext, ulfext);
			strcat(freqinfo,buf2);
		}
		m=1; uint8_t pbit_mcc=bits_to_uint(bits+n, m); n=n+m;
		if (pbit_mcc) {
			m=10; uint16_t mcc=bits_to_uint(bits+n, m); n=n+m;
			sprintf(buf2," MCC:%i",mcc);
			strcat(buf,buf2);
			sprintf(buf2," MCC:%4.4x",mcc);
			strcat(freqinfo,buf2);
		}

		m=1; uint8_t pbit_mnc=bits_to_uint(bits+n, m); n=n+m;
		if (pbit_mnc) {
			m=14; uint16_t mnc=bits_to_uint(bits+n, m); n=n+m;
			sprintf(buf2," MNC:%i",mnc);
			strcat(buf,buf2);
			sprintf(buf2," MNC:%4.4x",mnc);
			strcat(freqinfo,buf2);
		}

		m=1; uint8_t pbit_la=bits_to_uint(bits+n, m); n=n+m;
		if (pbit_la) {
			m=14; uint16_t la=bits_to_uint(bits+n, m); n=n+m;
			sprintf(buf2," LA:%i",la);
			strcat(buf,buf2);
			strcat(freqinfo,buf2);
		}

		m=1; uint8_t pbit_max_ms_txpower=bits_to_uint(bits+n, m); n=n+m;
		if (pbit_max_ms_txpower) {
			m=3; uint8_t max_ms_txpower=bits_to_uint(bits+n, m); n=n+m;
		}

		m=1; uint8_t pbit_min_rx_level=bits_to_uint(bits+n, m); n=n+m;
		if (pbit_min_rx_level) {
			m=4; uint8_t min_rx_level=bits_to_uint(bits+n, m); n=n+m;
		}

		m=1; uint8_t pbit_subscr_class=bits_to_uint(bits+n, m); n=n+m;
		if (pbit_subscr_class) {
			m=16; uint16_t subscr_class=bits_to_uint(bits+n, m); n=n+m;
		}

		m=1; uint8_t pbit_bs_srv_details=bits_to_uint(bits+n, m); n=n+m;
		if (pbit_bs_srv_details) {
			m=12; uint16_t bs_srv_details=bits_to_uint(bits+n, m); n=n+m;
		}

		m=1; uint8_t pbit_timeshare_info=bits_to_uint(bits+n, m); n=n+m;
		if (pbit_timeshare_info) {
			m=5; uint8_t timeshare_info=bits_to_uint(bits+n, m); n=n+m;
		}

		m=1; uint8_t pbit_tdma_frame_offset=bits_to_uint(bits+n, m); n=n+m;
		if (pbit_tdma_frame_offset) {
			m=6; uint8_t tdma_frame_offset=bits_to_uint(bits+n, m); n=n+m;
		}
	}
	sprintf(buf2,"] ");
	strcat(buf,buf2);
	printf("%s",buf);

	sprintf(buf2," RX:%i TETMON_end\r\n",tetra_hack_rxid);
	strcat(freqinfo,buf2);
	sendto(tetra_hack_live_socket, (char *)&freqinfo, strlen(freqinfo) + 1, 0, (struct sockaddr *)&tetra_hack_live_sockaddr, tetra_hack_socklen);

	return(n);
}

/* 18.4.1.4.1 sq5bpf */
int parse_d_nwrk_broadcast(struct tetra_mac_state *tms, struct msgb *msg, unsigned int len)
{
	uint8_t *bits = msg->l3h;
	int n,m,i;

	/* TMLE_PDISC_MLE 3 bits
	 * TMLE_PDUT_D_NWRK_BROADCAST 3 bits */
	n=3+3;

	m=16; uint16_t cell_reselect_parms=bits_to_uint(bits+n, m); n=n+m;
	m=2; uint16_t cell_load=bits_to_uint(bits+n, m); n=n+m;
	m=1; uint16_t optional_elements=bits_to_uint(bits+n, m); n=n+m;
	printf("\nD_NWRK_BROADCAST:[ cell_reselect:0x%4.4x cell_load:%i", cell_reselect_parms,cell_load);
	if (optional_elements) {
		m=1; uint16_t pbit_tetra_time=bits_to_uint(bits+n, m); n=n+m;
		if (pbit_tetra_time)
		{
			m=24; uint32_t tetra_time_utc=bits_to_uint(bits+n, m); n=n+m;
			m=1; uint8_t tetra_time_offset_sign=bits_to_uint(bits+n, m); n=n+m;
			m=6; uint8_t tetra_time_offset=bits_to_uint(bits+n, m); n=n+m;
			m=6; uint8_t tetra_time_year=bits_to_uint(bits+n, m); n=n+m;
			m=11; uint16_t tetra_time_reserved=bits_to_uint(bits+n, m); n=n+m; /* must be 0x7ff */
			printf(" time[secs:%i offset:%c%imin year:%i reserved:0x%4.4x]",tetra_time_utc,tetra_time_offset_sign?'-':'+',tetra_time_offset*15,2000+tetra_time_year,tetra_time_reserved);
			/* we could decode the time here, but it is not accurate on the networks that i see anyway */
		}


		m=1; uint16_t pbit_neigh_cells=bits_to_uint(bits+n, m); n=n+m;

		//	printf(" pbit_tetra_time:%i pbit_neigh_cells:%i",pbit_tetra_time,pbit_neigh_cells);
		if (pbit_neigh_cells)
		{
			m=3; uint16_t num_neigh_cells=bits_to_uint(bits+n, m); n=n+m;
			printf(" num_cells:%i",num_neigh_cells);
			for (i=0;i<num_neigh_cells;i++) {
				m=parse_nci_ca(bits+n); n=n+m;
			}
		}
	}
	printf("] RX:%i\n",tetra_hack_rxid);
	return 0;
}

int rx_mm_pdu(enum tetra_mm_pdu_type_d type, struct tetra_mac_state *tms, struct msgb *msg, unsigned int len)
{
	switch (type) {
	case TMM_PDU_T_D_OTAR:
		break;
	case TMM_PDU_T_D_AUTH:
		break;
	case TMM_PDU_T_D_CK_CHG_DEM:
		break;
	case TMM_PDU_T_D_DISABLE:
		break;
	case TMM_PDU_T_D_ENABLE:
		break;
	case TMM_PDU_T_D_LOC_UPD_ACC:
		break;
	case TMM_PDU_T_D_LOC_UPD_CMD:
		break;
	case TMM_PDU_T_D_LOC_UPD_REJ:
		break;
	case TMM_PDU_T_D_LOC_UPD_PROC:
		break;
	case TMM_PDU_T_D_ATT_DET_GRP:
		break;
	case TMM_PDU_T_D_ATT_DET_GRP_ACK:
		break;
	case TMM_PDU_T_D_MM_STATUS:
		break;
	case TMM_PDU_T_D_MM_PDU_NOTSUPP:
		break;
	default:
		break;
	}
	return 0;
}

/* sq5bpf */
int rx_cmce_pdu(enum tetra_cmce_pdu_type_d type, struct tetra_mac_state *tms, struct msgb *msg, unsigned int len)
{
	uint8_t * bits = msg->l3h;
	enum tetra_cmce_pdu_type_d cmce_type = bits_to_uint(bits + 3, 5);
	char tmpstr[4096] = {0};
	switch(cmce_type) {
		case TCMCE_PDU_T_D_ALERT:
			break;
		case TCMCE_PDU_T_D_CALL_PROCEEDING:
			break;
		case TCMCE_PDU_T_D_CONNECT:
			parse_d_connect(tms,msg,len);
			break;
		case TCMCE_PDU_T_D_CONNECT_ACK:
			parse_d_connect_ack(tms, msg, len);
			break;
		case TCMCE_PDU_T_D_DISCONNECT:

			break;
		case TCMCE_PDU_T_D_INFO:
			parse_d_info(tms, msg, len);
			break;
		case TCMCE_PDU_T_D_RELEASE:
			parse_d_release(tms,msg,len);
			break;
		case TCMCE_PDU_T_D_SETUP:
			parse_d_setup(tms,msg,len);
			break;
		case TCMCE_PDU_T_D_STATUS:
			parse_d_status(tms,msg,len);
			break;
		case TCMCE_PDU_T_D_TX_CEASED:
			parse_d_txceased(tms, msg, len);
			break;
		case TCMCE_PDU_T_D_TX_CONTINUE:
			break;
		case TCMCE_PDU_T_D_TX_GRANTED:
			parse_d_txgranted(tms,msg,len);
			break;
		case TCMCE_PDU_T_D_TX_WAIT:
			parse_d_txwait(tms, msg, len);
			break;
		case TCMCE_PDU_T_D_TX_INTERRUPT:
			parse_d_txinterrupt(tms, msg, len);
			break;
		case TCMCE_PDU_T_D_CALL_RESTORE:
			break;
		case TCMCE_PDU_T_D_SDS_DATA:
			sprintf(tmpstr,"TETMON_begin FUNC:SDS [%s] TETMON_end\r\n",osmo_ubit_dump(msg->l3h, len));
			sendto(tetra_hack_live_socket, (char *)&tmpstr, strlen((char *)&tmpstr)+1, 0, (struct sockaddr *)&tetra_hack_live_sockaddr, tetra_hack_socklen);
			parse_d_sds_data(tms,msg,len);
			break;
		case TCMCE_PDU_T_D_FACILITY:
			break;
//		case TCMCE_PDU_T_U_SDS_DATA:
//			/* Not sure if it works */
//			sprintf(tmpstr,"TETMON_begin FUNC:D-SDS [%s] TETMON_end\r\n",osmo_ubit_dump(msg->l3h, len));
//			sendto(tetra_hack_live_socket, (char *)&tmpstr, strlen((char *)&tmpstr)+1, 0, (struct sockaddr *)&tetra_hack_live_sockaddr, tetra_hack_socklen);
//			break;
		default:
			break;
	}
	return 0;
}

int rx_mle_pdu(enum tetra_cmce_pdu_type_d type, struct tetra_mac_state *tms, struct msgb *msg, unsigned int len)
{
	switch(type)
	{
	case TMLE_PDUT_D_NEW_CELL:
		break;
	case TMLE_PDUT_D_PREPARE_FAIL:
		break;
	case TMLE_PDUT_D_NWRK_BROADCAST:
		parse_d_nwrk_broadcast(tms,msg,len);
		break;
	case TMLE_PDUT_D_NWRK_BROADCAST_EXT:
		break;
	case TMLE_PDUT_D_RESTORE_ACK:
		break;
	case TMLE_PDUT_D_RESTORE_FAIL:
		break;
	case TMLE_PDUT_D_CHANNEL_RESPONSE:
		break;
	default:
		break;
	}
	return 0;
}
