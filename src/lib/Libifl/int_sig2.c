/*
 * Copyright (C) 1994-2019 Altair Engineering, Inc.
 * For more information, contact Altair at www.altair.com.
 *
 * This file is part of the PBS Professional ("PBS Pro") software.
 *
 * Open Source License Information:
 *
 * PBS Pro is free software. You can redistribute it and/or modify it under the
 * terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * PBS Pro is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.
 * See the GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Commercial License Information:
 *
 * For a copy of the commercial license terms and conditions,
 * go to: (http://www.pbspro.com/UserArea/agreement.html)
 * or contact the Altair Legal Department.
 *
 * Altair’s dual-license business model allows companies, individuals, and
 * organizations to create proprietary derivative works of PBS Pro and
 * distribute them - whether embedded or bundled with other software -
 * under a commercial license agreement.
 *
 * Use of Altair’s trademarks, including but not limited to "PBS™",
 * "PBS Professional®", and "PBS Pro™" and Altair’s logos is subject to Altair's
 * trademark licensing policies.
 *
 */

/**
 * @file	int_sig2.c
 */

#include <pbs_config.h>   /* the master config generated by configure */

#include <string.h>
#include <stdio.h>
#include "libpbs.h"
#include "dis.h"
#include "net_connect.h"
#include "tpp.h"



/**
 * @brief
 *	-PBS_sig_put.c Send the Signal Job Batch Request
 *
 * @param[in] c - socket descriptor
 * @param[in] jobid - job identifier
 * @param[in] signal - signal
 * @param[in] msg - msg to be sent
 * @param[in] extend - extention string for req encode
 * @param[in] prot - PROT_TCP or PROT_TPP
 * @param[in] msgid - msg id
 *
 * @return      int
 * @retval      0               Success
 * @retval      pbs_error(!0)   error
 */
int
PBSD_sig_put(int c, char *jobid, char *signal, char *extend, int prot, char **msgid)
{
	int rc;

	if ((rc = encode_DIS_ReqHdr(c, PBS_BATCH_SignalJob, pbs_current_user, prot, msgid)) ||
		(rc = encode_DIS_SignalJob(c, jobid, signal)) ||
		(rc = encode_DIS_ReqExtend(c, extend))) {
		if (prot == PROT_TCP) {
			if (set_conn_errtxt(c, dis_emsg[rc]) != 0) {
				return (pbs_errno = PBSE_SYSTEM);
			}
		}
		return (pbs_errno = PBSE_PROTOCOL);
	}
	if (dis_flush(c)) {
		pbs_errno = PBSE_PROTOCOL;
		rc = pbs_errno;
	}
	return rc;
}
