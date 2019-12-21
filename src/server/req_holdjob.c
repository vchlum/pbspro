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
/*
 * @file	svr_holdjob.c
 *
 * Functions relating to the Hold and Release Job Batch Requests.
 *
 * Included funtions are:
 *	req_holdjob()
 *	req_releasejob()
 *	chk_hold_priv()
 *	get_hold()
 *	post_hold()
 *
 */
#include <pbs_config.h>   /* the master config generated by configure */

#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include "libpbs.h"
#include "server_limits.h"
#include "list_link.h"
#include "attribute.h"
#include "server.h"
#include "credential.h"
#include "batch_request.h"
#include "net_connect.h"
#include "job.h"
#include "work_task.h"
#include "pbs_error.h"
#include "log.h"
#include "acct.h"
#include "pbs_nodes.h"
#include "svrfunc.h"


/* Private Functions Local to this file */

static int get_hold(pbs_list_head *, char **);
void post_hold(struct work_task *);

/* Global Data Items: */

extern struct server server;

extern char	*msg_jobholdset;
extern char	*msg_jobholdrel;
extern char	*msg_mombadhold;
extern char	*msg_postmomnojob;
extern time_t	 time_now;
extern job  *chk_job_request(char *, struct batch_request *, int *, int *);


int chk_hold_priv(long val, int perm);

/* Private Data */

static attribute temphold;

/**
 * @brief
 * 		chk_hold_priv - check that client has privilege to set/clear hold
 *
 * @param[in]	val	- hold bits being changed
 * @param[in]	perm	- client privilege
 *
 * @return	error code
 * @retval	0	- success
 * @retval	!=0	- failure
 */

int
chk_hold_priv(long val, int perm)
{
	if ((val & HOLD_s) && ((perm & ATR_DFLAG_MGWR) == 0))
		return (PBSE_PERM);
	if ((val & HOLD_o) && ((perm & (ATR_DFLAG_MGWR|ATR_DFLAG_OPWR)) == 0))
		return (PBSE_PERM);
	return (PBSE_NONE);
}


/**
 * @brief
 * 		req_holdjob - service the Hold Job Request
 *
 *		This request sets one or more holds on a job.
 *		The state of the job may change as a result.
 *
 * @param[in,out]	preq	- Job Request
 */

void
req_holdjob(struct batch_request *preq)
{
	long *hold_val;
	int jt;		/* job type */
	int newstate;
	int newsub;
	long old_hold;
	job *pjob;
	char *pset;
	char jid[PBS_MAXSVRJOBID + 1];
	int rc;
	char date[32];
	time_t now;
	int err = PBSE_NONE;

	snprintf(jid, sizeof(jid), "%s", preq->rq_ind.rq_hold.rq_orig.rq_objname);

	pjob = chk_job_request(jid, preq, &jt, &err);
	if (pjob == NULL) {
		pjob = find_job(jid);
		if (pjob != NULL && pjob->ji_pmt_preq != NULL)
			reply_preempt_jobs_request(err, PREEMPT_METHOD_CHECKPOINT, pjob);
		return;
	}
	if ((jt != IS_ARRAY_NO) && (jt != IS_ARRAY_ArrayJob)) {
		/*
		 * We need to find the job again because chk_job_request() will return
		 * the parent array if the job is a subjob.
		 */
		pjob = find_job(jid);
		if (pjob != NULL && pjob->ji_pmt_preq != NULL)
			reply_preempt_jobs_request(PBSE_IVALREQ, PREEMPT_METHOD_CHECKPOINT, pjob);
		req_reject(PBSE_IVALREQ, 0, preq);
		return;
	}
	if ((pjob->ji_qs.ji_state == JOB_STATE_RUNNING) &&
		(pjob->ji_qs.ji_substate == JOB_SUBSTATE_PROVISION)) {
		if (pjob->ji_pmt_preq != NULL)
			reply_preempt_jobs_request(PBSE_BADSTATE, PREEMPT_METHOD_CHECKPOINT, pjob);

		req_reject(PBSE_BADSTATE, 0, preq);
		return;
	}

	/* cannot do anything until we decode the holds to be set */

	if ((rc = get_hold(&preq->rq_ind.rq_hold.rq_orig.rq_attr, &pset)) != 0) {
		if (pjob->ji_pmt_preq != NULL)
			reply_preempt_jobs_request(rc, PREEMPT_METHOD_CHECKPOINT, pjob);
		req_reject(rc, 0, preq);
		return;
	}

	/* if other than HOLD_u is being set, must have privil */

	if ((rc = chk_hold_priv(temphold.at_val.at_long, preq->rq_perm)) != 0) {
		if (pjob->ji_pmt_preq != NULL)
			reply_preempt_jobs_request(rc, PREEMPT_METHOD_CHECKPOINT, pjob);

		req_reject(rc, 0, preq);
		return;
	}

	/* HOLD_bad_password can only be done by root or admin */
	if ( (temphold.at_val.at_long & HOLD_bad_password) && \
		  strcasecmp(preq->rq_user, PBS_DEFAULT_ADMIN) != 0 ) {
		if (pjob->ji_pmt_preq != NULL)
			reply_preempt_jobs_request(PBSE_PERM, PREEMPT_METHOD_CHECKPOINT, pjob);

		req_reject(PBSE_PERM, 0, preq);
		return;
	}

	hold_val = &pjob->ji_wattr[(int)JOB_ATR_hold].at_val.at_long;
	old_hold = *hold_val;
	*hold_val |= temphold.at_val.at_long;
	pjob->ji_wattr[(int)JOB_ATR_hold].at_flags |= ATR_VFLAG_SET | ATR_VFLAG_MODCACHE;

	/* Note the hold time in the job comment. */
	now = time(NULL);
	(void)strncpy(date, (const char *)ctime(&now), 24);
	date[24] = '\0';
	(void)sprintf(log_buffer, "Job held by %s on %s", preq->rq_user, date);
	job_attr_def[(int)JOB_ATR_Comment].at_decode(&pjob->ji_wattr[(int)JOB_ATR_Comment], NULL, NULL, log_buffer);

	(void)sprintf(log_buffer, msg_jobholdset, pset, preq->rq_user,
		preq->rq_host);

	if ((pjob->ji_qs.ji_state == JOB_STATE_RUNNING) &&
		(pjob->ji_qs.ji_substate != JOB_SUBSTATE_PRERUN) &&
		(pjob->ji_wattr[(int)JOB_ATR_chkpnt].at_val.at_str) &&
		(*pjob->ji_wattr[(int)JOB_ATR_chkpnt].at_val.at_str != 'n')) {

		/* have MOM attempt checkpointing */

		if ((rc = relay_to_mom(pjob, preq, post_hold)) != 0) {
			*hold_val = old_hold;	/* reset to the old value */
			if (pjob->ji_pmt_preq != NULL)
				reply_preempt_jobs_request(rc, PREEMPT_METHOD_CHECKPOINT, pjob);
			req_reject(rc, 0, preq);
		} else {
			pjob->ji_qs.ji_svrflags |=
				(JOB_SVFLG_HASRUN | JOB_SVFLG_CHKPT | JOB_SVFLG_HASHOLD);
			(void)job_save(pjob, SAVEJOB_QUICK);
			log_event(PBSEVENT_JOB, PBS_EVENTCLASS_JOB, LOG_INFO,
				pjob->ji_qs.ji_jobid, log_buffer);
		}
	} else {

		/* every thing went well, may need to update the job state */

		log_event(PBSEVENT_JOB, PBS_EVENTCLASS_JOB, LOG_INFO,
			pjob->ji_qs.ji_jobid, log_buffer);
		if (old_hold != *hold_val) {
			/* indicate attributes changed     */
			pjob->ji_modified = 1;
			svr_evaljobstate(pjob, &newstate, &newsub, 0);
			(void)svr_setjobstate(pjob, newstate, newsub);
		}
		/* Reject preemption because job requested -c n */
		if (pjob->ji_pmt_preq != NULL)
			reply_preempt_jobs_request(PBSE_NOSUP, PREEMPT_METHOD_CHECKPOINT, pjob);
		reply_ack(preq);
	}
}


/**
 * @brief
 * 		req_releasejob - service the Release Job Request
 *
 *		This request clears one or more holds on a job.
 *		As a result, the job might change state.
 *
 * @param[in]	preq	- ptr to the decoded request
 */

void
req_releasejob(struct batch_request *preq)
{
	int              jt;            /* job type */
	int		 newstate;
	int		 newsub;
	long		 old_hold;
	job		*pjob;
	char		*pset;
	int		 rc;


	pjob = chk_job_request(preq->rq_ind.rq_release.rq_objname, preq, &jt, NULL);
	if (pjob == NULL)
		return;

	if ((jt != IS_ARRAY_NO) && (jt != IS_ARRAY_ArrayJob)) {
		req_reject(PBSE_IVALREQ, 0, preq);
		return;
	}

	/* cannot do anything until we decode the holds to be set */

	if ((rc = get_hold(&preq->rq_ind.rq_hold.rq_orig.rq_attr, &pset)) != 0) {
		req_reject(rc, 0, preq);
		return;
	}

	/* if other than HOLD_u is being released, must have privil */

	if ((rc = chk_hold_priv(temphold.at_val.at_long, preq->rq_perm)) != 0) {
		req_reject(rc, 0, preq);
		return;
	}

	/* all ok so far, unset the hold */

	old_hold = pjob->ji_wattr[(int)JOB_ATR_hold].at_val.at_long;
	rc = job_attr_def[(int)JOB_ATR_hold].
		at_set(&pjob->ji_wattr[(int)JOB_ATR_hold],
		&temphold, DECR);
	if (rc) {
		req_reject(rc, 0, preq);
		return;
	}

	/* every thing went well, if holds changed, update the job state */

#ifndef NAS /* localmod 105 Always reset etime on release */
	if (old_hold != pjob->ji_wattr[(int)JOB_ATR_hold].at_val.at_long) {
#endif /* localmod 105 */
#ifdef NAS /* localmod 105 */
		{
			attribute *etime = &pjob->ji_wattr[(int)JOB_ATR_etime];
			etime->at_val.at_long = time_now;
			etime->at_flags |= ATR_VFLAG_SET|ATR_VFLAG_MODCACHE;
#endif /* localmod 105 */
		pjob->ji_modified = 1;	/* indicates attributes changed    */
		svr_evaljobstate(pjob, &newstate, &newsub, 0);
		(void)svr_setjobstate(pjob, newstate, newsub); /* saves job */

	}

	if ((jt == IS_ARRAY_ArrayJob) && (pjob->ji_ajtrk)) {
		int i;
		for(i = 0 ; i < pjob->ji_ajtrk->tkm_ct ; i++) {
			job *psubjob = pjob->ji_ajtrk->tkm_tbl[i].trk_psubjob;
			if (psubjob && (psubjob->ji_qs.ji_state == JOB_STATE_HELD)) {
#ifndef NAS
				old_hold = psubjob->ji_wattr[(int)JOB_ATR_hold].at_val.at_long;
				rc =
#endif
					job_attr_def[(int)JOB_ATR_hold].
					at_set(&psubjob->ji_wattr[(int)JOB_ATR_hold],
					&temphold, DECR);
#ifndef NAS /* localmod 105 Always reset etime on release */
				if (!rc && (old_hold != psubjob->ji_wattr[(int)JOB_ATR_hold].at_val.at_long)) {
#endif /* localmod 105 */
#ifdef NAS /* localmod 105 */
				{
					attribute *etime = &psubjob->ji_wattr[(int)JOB_ATR_etime];
					etime->at_val.at_long = time_now;
					etime->at_flags |= ATR_VFLAG_SET|ATR_VFLAG_MODCACHE;
#endif /* localmod 105 */
					psubjob->ji_modified = 1;	/* indicates attributes changed    */
					svr_evaljobstate(psubjob, &newstate, &newsub, 0);
					(void)svr_setjobstate(psubjob, newstate, newsub); /* saves job */
				}
				if (psubjob->ji_wattr[(int)JOB_ATR_hold].at_val.at_long == HOLD_n)
					job_attr_def[(int)JOB_ATR_Comment].at_free(&psubjob->ji_wattr[(int)JOB_ATR_Comment]);
				(void)sprintf(log_buffer, msg_jobholdrel, pset, preq->rq_user,
					preq->rq_host);
				log_event(PBSEVENT_JOB, PBS_EVENTCLASS_JOB, LOG_INFO,
					psubjob->ji_qs.ji_jobid, log_buffer);
			}
		}
	}
	if (pjob->ji_wattr[(int)JOB_ATR_hold].at_val.at_long == HOLD_n) {
		if ((jt == IS_ARRAY_ArrayJob) && (pjob->ji_qs.ji_stime != 0) ) {
			char timebuf[128];

			strftime(timebuf, 128, "%a %b %d at %H:%M", localtime(&pjob->ji_qs.ji_stime));
			sprintf(log_buffer, "Job Array Began at %s", timebuf);

			job_attr_def[(int)JOB_ATR_Comment].at_decode(&pjob->ji_wattr[(int)JOB_ATR_Comment], NULL, NULL, log_buffer);
		} else
			job_attr_def[(int)JOB_ATR_Comment].at_free(&pjob->ji_wattr[(int)JOB_ATR_Comment]);
	}
	(void)sprintf(log_buffer, msg_jobholdrel, pset, preq->rq_user,
		preq->rq_host);
	log_event(PBSEVENT_JOB, PBS_EVENTCLASS_JOB, LOG_INFO,
		pjob->ji_qs.ji_jobid, log_buffer);
	reply_ack(preq);
}

/**
 * @brief
 * 		get_hold - search a list of attributes (svrattrl) for the hold-types
 * 		attribute.  This is used by the Hold Job and Release Job request,
 *		therefore it is an error if the hold-types attribute is not present,
 *		or there is more than one.
 *
 *		Decode the hold attribute into temphold.
 *
 * @param[in]	phead	- pbs list head.
 * @param[out]	pset	- RETURN - ptr to hold value
 *
 * @return	error code
 */

static int
get_hold(pbs_list_head *phead, char **pset)
{
	int		 have_one = 0;
	struct svrattrl *holdattr = NULL;
	struct svrattrl *pal;

	pal = (struct svrattrl *)GET_NEXT((*phead));
	while (pal) {
		if (!strcasecmp(pal->al_name, job_attr_def[(int)JOB_ATR_hold].at_name)) {
			holdattr = pal;
			*pset    = pal->al_value;
			have_one++;
		} else {
			return (PBSE_IVALREQ);
		}
		pal = (struct svrattrl *)GET_NEXT(pal->al_link);
	}
	if (have_one != 1)
		return (PBSE_IVALREQ);

	/* decode into temporary attribute structure */

	clear_attr(&temphold, &job_attr_def[(int)JOB_ATR_hold]);
	return (job_attr_def[(int)JOB_ATR_hold].at_decode(
		&temphold,
		holdattr->al_name,
		NULL,
		holdattr->al_value));
}


/**
 * @brief
 * 		"post hold" - A round hole in the ground in which a post is placed :-)
 *		This function is called when a hold request which was sent to Mom has
 *		been responed to by MOM.  The hold request for the running job is
 *		completed and replied to based on what was returned by Mom.
 *
 *		If Mom repies with:
 *	  	No error (0) - job is marked as checkpointed;
 *	  	PBSE_NOSUP - checkpoint in not supported,  job just has hold type set;
 *	  	PBSE_CKPBSY - a prior checkpoint is still in progress;
 *	  	For any error other than PBSE_NOSUP, a message is logged and returned
 *	  	to the client.
 *
 * @param[in]	pwt	- pointer to work task entry holding information about the
 *				original client "hold job" request.
 *
 * @return void
 */

void
post_hold(struct work_task *pwt)
{
	int			code;
	job			*pjob;
	struct batch_request	*preq;
	conn_t			*conn;

	if (pwt->wt_aux2 != 1)
		svr_disconnect(pwt->wt_event);	/* close connection to MOM */
	preq = pwt->wt_parm1;
	code = preq->rq_reply.brp_code;
	preq->rq_conn = preq->rq_orgconn;	/* restore client socket */

	pjob = find_job(preq->rq_ind.rq_hold.rq_orig.rq_objname);

	if (pjob == NULL) {
		log_event(PBSEVENT_DEBUG, PBS_EVENTCLASS_JOB, LOG_DEBUG,
			  preq->rq_ind.rq_hold.rq_orig.rq_objname,
			  msg_postmomnojob);
		req_reject(PBSE_UNKJOBID, 0, preq);
		return;
	}

	if (pwt->wt_aux2 != PROT_TPP) {
		conn = get_conn(preq->rq_conn);

		if (!conn) {
			if (pjob->ji_pmt_preq != NULL)
				reply_preempt_jobs_request(PBSE_SYSTEM, PREEMPT_METHOD_CHECKPOINT, pjob);
			req_reject(PBSE_SYSTEM, 0, preq);
			return;
		}

		conn->cn_authen &= ~PBS_NET_CONN_NOTIMEOUT;
	}

	if (code != 0) {
		/* Checkpoint failed, remove checkpoint flags from job */
		pjob->ji_qs.ji_svrflags &= ~(JOB_SVFLG_HASHOLD | JOB_SVFLG_CHKPT);
		if (code != PBSE_NOSUP) {
			/* a "real" error - log message with return error code */
			(void)sprintf(log_buffer, msg_mombadhold, code);
			log_event(PBSEVENT_DEBUG, PBS_EVENTCLASS_JOB, LOG_DEBUG,
				pjob->ji_qs.ji_jobid, log_buffer);
			/* send message back to server for display to user */
			if (pjob->ji_pmt_preq != NULL)
				reply_preempt_jobs_request(code, PREEMPT_METHOD_CHECKPOINT, pjob);
			reply_text(preq, code, log_buffer);
			return;
		}
	} else if (code == 0) {

		/* record that MOM has a checkpoint file */
		pjob->ji_qs.ji_substate = JOB_SUBSTATE_RERUN;
		if (preq->rq_reply.brp_auxcode)	/* chkpt can be moved */
			pjob->ji_qs.ji_svrflags =
				(pjob->ji_qs.ji_svrflags & ~JOB_SVFLG_CHKPT) |
			JOB_SVFLG_HASRUN | JOB_SVFLG_ChkptMig;

		pjob->ji_modified = 1;	  /* indicate attributes changed     */
		(void)job_save(pjob, SAVEJOB_QUICK);

		/* note in accounting file */

		account_record(PBS_ACCT_CHKPNT, pjob, NULL);
	}
	if (pjob->ji_pmt_preq != NULL)
		reply_preempt_jobs_request(PBSE_NONE, PREEMPT_METHOD_CHECKPOINT, pjob);

	reply_ack(preq);
}
