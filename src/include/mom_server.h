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
#ifndef	_MOM_SERVER_H
#define	_MOM_SERVER_H
#ifdef	__cplusplus
extern "C" {
#endif


#ifndef	_LIST_LINK_H
#include "list_link.h"
#endif

/*
 * Definition of basic structures and functions used for Mom -> Server
 * TPP communication.
 *
 * Job Obituary/Resource Usage requests...
 *
 * These are from Mom to Server only and only via TPP
 */

struct resc_used_update {
	struct resc_used_update	*ru_next;
	char 			*ru_pjobid;	/* pointer to job id         */
	char			*ru_comment;	/* a general message	     */
	int			 ru_status;	/* job exit status (or zero) */
	int			 ru_hop;	/* hop/run count of job	*/
	pbs_list_head		 ru_attr;	/* list of svrattrl */
};

#define FREE_RUU(x) \
	free_attrlist(&x->ru_attr); \
	(void)free(x->ru_pjobid); \
	if (x->ru_comment) (void)free(x->ru_comment); \
	(void)free(x);

extern void	send_resc_used(int cmd, int count,
	struct resc_used_update *ptop);
extern void	ack_obit(int stream, char *jobid);
extern void	reject_obit(int stream, char *jobid);
extern void	job_obit(struct resc_used_update *, int s);

extern char	mom_short_name[];

#ifdef	_PBS_JOB_H
extern u_long	resc_used(job *, char *, u_long(*func)(resource *pres));
#endif	/* _PBS_JOB_H */
#ifdef	__cplusplus
}
#endif
#endif	/* _MOM_SERVER_H */
