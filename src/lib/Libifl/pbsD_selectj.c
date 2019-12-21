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
 * @file	pbsD_selectj.c
 * @brief
 *	This file contines two main library entries:
 *		pbs_selectjob()
 *		pbs_selstat()
 *
 *
 *	pbs_selectjob() - the SelectJob request
 *		Return a list of job ids that meet certain selection criteria.
 */

#include <pbs_config.h>   /* the master config generated by configure */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "libpbs.h"
#include "dis.h"
#include "pbs_ecl.h"


static int PBSD_select_put(int, int, struct attropl *, struct attrl *, char *);
static char **PBSD_select_get(int);

/**
 * @brief
 *	-the SelectJob request
 *	Return a list of job ids that meet certain selection criteria.
 *
 * @param[in] c - communication handle
 * @param[in] attrib - pointer to attropl structure(selection criteria)
 * @param[in] extend - extend string to encode req
 *
 * @return	string
 * @retval	job ids		success
 * @retval	NULL		error
 *
 */
char **
__pbs_selectjob(int c, struct attropl *attrib, char *extend)
{
	char **ret = NULL;

	/* initialize the thread context data, if not already initialized */
	if (pbs_client_thread_init_thread_context() != 0)
		return NULL;

	/* first verify the attributes, if verification is enabled */
	if (pbs_verify_attributes(c, PBS_BATCH_SelectJobs, MGR_OBJ_JOB,
		MGR_CMD_NONE, attrib))
		return NULL;

	/* lock pthread mutex here for this connection */
	/* blocking call, waits for mutex release */
	if (pbs_client_thread_lock_connection(c) != 0)
		return NULL;

	if (PBSD_select_put(c, PBS_BATCH_SelectJobs, attrib, NULL, extend) == 0)
		ret = PBSD_select_get(c);

	/* unlock the thread lock and update the thread context data */
	if (pbs_client_thread_unlock_connection(c) != 0) {
		/* Even though ret is a char **, PBSD_select_get() allocated all its memory in one malloc() */
		free(ret);
		return NULL;
	}

	return ret;
}

/**
 * @brief
 * 	-pbs_selstat() - Selectable status
 *	Return status information for jobs that meet certain selection
 *	criteria.  This is a short-cut combination of pbs_selecljob()
 *	and repeated pbs_statjob().
 *
 * @param[in] c - communication handle
 * @param[in] attrib - pointer to attropl structure(selection criteria)
 * @param[in] extend - extend string to encode req
 * @param[in] rattrib - list of attributes to return
 *
 * @return      structure handle
 * @retval      list of attr	success
 * @retval      NULL		error
 *
 */

struct batch_status *
__pbs_selstat(int c, struct attropl *attrib, struct attrl   *rattrib, char *extend)
{
	struct batch_status *ret = NULL;
	extern struct batch_status *PBSD_status_get(int c);

	/* initialize the thread context data, if not already initialized */
	if (pbs_client_thread_init_thread_context() != 0)
		return NULL;

	/* first verify the attributes, if verification is enabled */
	if (pbs_verify_attributes(c, PBS_BATCH_SelectJobs, MGR_OBJ_JOB,
		MGR_CMD_NONE, attrib))
		return NULL;

	/* lock pthread mutex here for this connection */
	/* blocking call, waits for mutex release */
	if (pbs_client_thread_lock_connection(c) != 0)
		return NULL;


	if (PBSD_select_put(c, PBS_BATCH_SelStat, attrib, rattrib, extend) == 0)
		ret = PBSD_status_get(c);

	/* unlock the thread lock and update the thread context data */
	if (pbs_client_thread_unlock_connection(c) != 0)
		return NULL;

	return ret;
}


/**
 * @brief
 *	-encode and puts selectjob request  data
 *
 * @param[in] c - communication handle
 * @param[in] type - type of request
 * @param[in] attrib - pointer to attropl structure(selection criteria)
 * @param[in] extend - extend string to encode req
 * @param[in] rattrib - list of attributes to return
 *
 * @return      int
 * @retval      0	success
 * @retval      !0	error
 *
 */
static int
PBSD_select_put(int c, int type, struct attropl *attrib, struct attrl *rattrib, char *extend)
{
	int rc;

	if ((rc = encode_DIS_ReqHdr(c, type, pbs_current_user, PROT_TCP, NULL)) ||
		(rc = encode_DIS_attropl(c, attrib)) ||
		(rc = encode_DIS_attrl(c, rattrib))  ||
		(rc = encode_DIS_ReqExtend(c, extend))) {
		if (set_conn_errtxt(c, dis_emsg[rc]) != 0) {
			pbs_errno = PBSE_SYSTEM;
		} else {
			pbs_errno = PBSE_PROTOCOL;
		}
		return (pbs_errno);
	}

	/* write data */

	if (dis_flush(c)) {
		return (pbs_errno = PBSE_PROTOCOL);
	}

	return 0;
}

/**
 * @brief
 *	-reads selectjob reply from stream
 *
 * @param[in] c - communication handle
 *
 * @return	string list
 * @retval	list of strings		success
 * @retval	NULL			error
 *
 */
static char **
PBSD_select_get(int c)
{
	int   i;
	struct batch_reply *reply;
	int   njobs;
	char *sp;
	int   stringtot;
	size_t totsize;
	struct brp_select *sr;
	char **retval = NULL;

	/* read reply from stream */

	reply = PBSD_rdrpy(c);
	if (reply == NULL) {
		pbs_errno = PBSE_PROTOCOL;
	} else if (reply->brp_choice != BATCH_REPLY_CHOICE_NULL &&
		reply->brp_choice != BATCH_REPLY_CHOICE_Text &&
		reply->brp_choice != BATCH_REPLY_CHOICE_Select) {
		pbs_errno = PBSE_PROTOCOL;
	} else if (get_conn_errno(c) == 0) {
		/* process the reply -- first, build a linked
		 list of the strings we extract from the reply, keeping
		 track of the amount of space used...
		 */
		stringtot = 0;
		njobs = 0;
		sr = reply->brp_un.brp_select;
		while (sr != NULL) {
			stringtot += strlen(sr->brp_jobid) + 1;
			njobs++;
			sr = sr->brp_next;
		}
		/* ...then copy all the strings into one of "Bob's
		 structures", freeing all strings we just allocated...
		 */

		totsize = stringtot + (njobs + 1) * (sizeof(char *));
		retval = (char **)malloc(totsize);
		if (retval == NULL) {
			pbs_errno = PBSE_SYSTEM;
			PBSD_FreeReply(reply);
			return NULL;
		}
		sr = reply->brp_un.brp_select;
		sp = (char *)retval + (njobs + 1) * sizeof(char *);
		for (i = 0; i < njobs; i++) {
			retval[i] = sp;
			strcpy(sp, sr->brp_jobid);
			sp += strlen(sp) + 1;
			sr = sr->brp_next;
		}
		retval[i] = NULL;
	}

	PBSD_FreeReply(reply);

	return retval;
}
