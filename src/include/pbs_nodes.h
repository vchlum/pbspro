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
#ifndef	_PBS_NODES_H
#define	_PBS_NODES_H
#ifdef	__cplusplus
extern "C" {
#endif



/*
 *	Header file used for the node tracking routines.
 */

#include "resv_node.h"
#include "resource.h"
#include "job.h"

#include "libutil.h"
#ifndef PBS_MOM
#include "pbs_db.h"
extern pbs_db_conn_t	*svr_db_conn;
#endif


#include "pbs_array_list.h"
#include "hook.h"
#include "hook_func.h"

/* Attributes in the Server's vnode (old node) object */
enum nodeattr {
	ND_ATR_Mom,
	ND_ATR_Port,
	ND_ATR_version,
	ND_ATR_ntype,
	ND_ATR_state,
	ND_ATR_pcpus,
	ND_ATR_priority,
	ND_ATR_jobs,
	ND_ATR_MaxRun,
	ND_ATR_MaxUserRun,
	ND_ATR_MaxGrpRun,
	ND_ATR_No_Tasks,
	ND_ATR_PNames,
	ND_ATR_resvs,
	ND_ATR_ResourceAvail,
	ND_ATR_ResourceAssn,
	ND_ATR_Queue,
	ND_ATR_Comment,
	ND_ATR_ResvEnable,
	ND_ATR_NoMultiNode,
	ND_ATR_Sharing,
	ND_ATR_ProvisionEnable,
	ND_ATR_current_aoe,	/* current AOE instantiated */
	ND_ATR_in_multivnode_host,
	ND_ATR_MaintJobs,
	ND_ATR_License,
	ND_ATR_LicenseInfo,
	ND_ATR_TopologyInfo,
	ND_ATR_vnode_pool,
	ND_ATR_Power_Provisioning,
	ND_ATR_current_eoe,     /* current EOE instantiated */
	ND_ATR_partition,
	ND_ATR_poweroff_eligible,	/* Node can be powered-off */
	ND_ATR_last_state_change_time,	/* Node's state changed at */
	ND_ATR_last_used_time,		/* Node was last busy at */
	ND_ATR_LAST	/* WARNING: Must be the highest valued enum */
};


#ifndef PBS_MAXNODENAME
#define PBS_MAXNODENAME	79
#endif

/*
 * mominfo structure - used by both the Server and Mom
 *	to hold contact	information for an instance of a pbs_mom on a host
 */

struct mominfo {
	char		mi_host[PBS_MAXHOSTNAME+1]; /* hostname where mom is */
	unsigned int	mi_port;	/* port to which Mom is listening */
	unsigned int	mi_rmport;	/* port for MOM RM communication */
	time_t		mi_modtime;	/* time configuration changed */
	void	       *mi_data;	/* daemon dependent substructure */
	mom_hook_action_t **mi_action;	/* pending hook copy/delete on mom */
	int		mi_num_action; /* # of hook actions in mi_action */
};
typedef struct mominfo mominfo_t;

/*
 * The following structure is used by the Server for each Mom.
 * It is pointed to by the mi_data element in mominfo_t
 */

struct mom_svrinfo {
	unsigned long msr_state;   /* Mom's state */
	long	      msr_pcpus;   /* number of physical cpus reported by Mom */
	long	      msr_acpus;   /* number of avail    cpus reported by Mom */
	u_Long	      msr_pmem;	   /* amount of physical mem  reported by Mom */
	int	      msr_numjobs; /* number of jobs on this node */
	char	     *msr_arch;	    /* reported "arch" */
	char	     *msr_pbs_ver;  /* mom's reported "pbs_version" */
	int	      msr_stream;   /* TPP stream to Mom */
	time_t	      msr_timedown; /* time Mom marked down */
	time_t	      msr_timeinit; /* time Mom marked initializing */
	time_t        msr_timepinged; /* time Mom was last pinged */
	struct work_task *msr_wktask;	/* work task for reque jobs */
	pbs_list_head	msr_deferred_cmds;	/* links to svr work_task list for TPP replies */
	unsigned long *msr_addrs;   /* IP addresses of host */
	int	      msr_numvnds;  /* number of vnodes */
	int	      msr_numvslots; /* number of slots in msr_children */
	struct pbsnode **msr_children;  /* array of vnodes supported by Mom */
	int	      msr_jbinxsz;  /* size of job index array */
	struct job  **msr_jobindx;  /* index array of jobs on this Mom */
	long	      msr_vnode_pool;/* the pool of vnodes that belong to this Mom */
};
typedef struct mom_svrinfo mom_svrinfo_t;

struct vnpool_mom {
	long			vnpm_vnode_pool;
	int			vnpm_nummoms;
	mominfo_t	       *vnpm_inventory_mom;
	mominfo_t	      **vnpm_moms;
	struct vnpool_mom      *vnpm_next;
};
typedef struct vnpool_mom vnpool_mom_t;

#ifdef	PBS_MOM

enum vnode_sharing_state	{ isshared = 0, isexcl = 1 };
enum rlplace_value		{ rlplace_unset = 0,
	rlplace_share = 1,
	rlplace_excl = 2 };

extern enum vnode_sharing_state vnss[][rlplace_excl - rlplace_unset + 1];

/*
 *	The following information is used by pbs_mom to track per-Mom
 *	information.  The mi_data member of a mominfo_t structure points to it.
 */
struct mom_vnodeinfo {
	char		*mvi_id;	/* vnode ID */
	enum vnode_sharing	mvi_sharing;	/* declared "sharing" value */
	unsigned int	mvi_memnum;	/* memory board node ID */
	unsigned int	mvi_ncpus;	/* number of CPUs in mvi_cpulist[] */
	unsigned int	mvi_acpus;	/* of those, number of CPUs available */
	struct mvi_cpus {
		unsigned int	mvic_cpunum;
#define	MVIC_FREE	0x1
#define	MVIC_ASSIGNED	0x2
#define	MVIC_CPUISFREE(m, j)	(((m)->mvi_cpulist[j].mvic_flags) & MVIC_FREE)
		unsigned int	mvic_flags;
		job		*mvic_job;	/* job this CPU is assigned */
	} *mvi_cpulist;				/* CPUs owned by this vnode */
};
typedef struct mvi_cpus		mom_mvic_t;
typedef struct mom_vnodeinfo	mom_vninfo_t;

extern enum rlplace_value getplacesharing(job *pjob);

#endif	/* PBS_MOM */


/* The following are used by Mom to map vnodes to the parent host */

struct  mom_vnode_map {
	char	   mvm_name[PBS_MAXNODENAME+1];
	char	  *mvm_hostn;	/* host name for MPI via PBS_NODEFILE */
	int	   mvm_notask;
	mominfo_t *mvm_mom;
};
typedef struct mom_vnode_map momvmap_t;

/* used for generation control on the Host to Vnode mapping */
struct	mominfo_time {
	time_t	   mit_time;
	int	   mit_gen;
};
typedef struct mominfo_time mominfo_time_t;

extern momvmap_t **mommap_array;
extern int	   mommap_array_size;
extern mominfo_time_t	   mominfo_time;


struct	prop {
	char	*name;
	short	mark;
	struct	prop	*next;
};

struct	jobinfo {
	struct	job	*job;
	int		has_cpu;
	size_t		mem;
	struct	jobinfo	*next;
};

struct	resvinfo {
	resc_resv	*resvp;
	struct resvinfo *next;
};

struct node_req {
	int	 nr_ppn;	/* processes (tasks) per node */
	int	 nr_cpp;	/* cpus per process           */
	int	 nr_np;		/* nr_np = nr_ppn * nr_cpp    */
};


/* virtual cpus - one for each resource_available.ncpus on a vnode */
struct	pbssubn {
	struct pbssubn	*next;
	struct jobinfo	*jobs;
	unsigned long	 inuse;
	long		 index;
};

union ndu_ninfo {
	struct {
		unsigned int __nd_lic_info:24;	/* OEM license information */
		unsigned int __nd_spare:8;	/* unused bits in this integer */
	} __ndu_bitfields;
	unsigned int	__nd_int;
};

/*
 * Vnode structure
 */
struct	pbsnode {
	char			*nd_name;	/* vnode's name */
	struct mominfo		**nd_moms;	/* array of parent Moms */
	int			 nd_nummoms;	/* number of Moms */
	int			 nd_nummslots;	/* number of slots in nd_moms */
	int			 nd_index;	/* global node index */
	int			 nd_arr_index;	/* index of myself in the svr node array, only in mem, not db */
	char			*nd_hostname;	/* ptr to hostname */
	struct pbssubn		*nd_psn;	/* ptr to list of virt cpus */
	struct resvinfo		*nd_resvp;
	long			 nd_nsn;	/* number of VPs  */
	long			 nd_nsnfree;	/* number of VPs free */
	long			 nd_ncpus;	/* number of phy cpus on node */
	short			 nd_written;	/* written to nodes file */
	unsigned long		 nd_state;	/* state of node */
	unsigned short	 	 nd_ntype;	/* node type */
	unsigned short		 nd_accted;	/* resc recorded in job acct */
	struct pbs_queue	*nd_pque;	/* queue to which it belongs */
	int			 nd_modified;	/* flag indicating whether state update is required */
	attribute		 nd_attr[ND_ATR_LAST];
};

enum	warn_codes { WARN_none, WARN_ngrp_init, WARN_ngrp_ck, WARN_ngrp };
enum	nix_flags { NIX_none, NIX_qnodes, NIX_nonconsume };
enum	part_flags { PART_refig, PART_add, PART_rmv };

#define NDPTRBLK	50	/* extend a node ptr array by this amt */


/*
 * The following INUSE_* flags are used for several structures
 * (subnode.inuse, node.nd_state, and mom_svrinfo.msr_state).
 * The database schema stores node.nd_state as a 4 byte integer.
 * If more than 32 flags bits need to be added, the database schema will
 * need to be updated.  If not, the excess flags will be lost upon server restart
 */
#define	INUSE_FREE	 0x00	/* Node has one or more avail VPs	*/
#define	INUSE_OFFLINE	 0x01	/* Node was removed by administrator	*/
#define	INUSE_DOWN	 0x02	/* Node is down/unresponsive 		*/
#define	INUSE_DELETED	 0x04	/* Node is "deleted"			*/
#define INUSE_UNRESOLVABLE	 0x08	/* Node not reachable */
#define	INUSE_JOB	 0x10	/* VP   in used by a job (normal use)	*/
/* Node all VPs in use by jobs		*/
#define INUSE_STALE	 0x20	/* Vnode not reported by Mom            */
#define INUSE_JOBEXCL	 0x40	/* Node is used by one job (exclusive)	*/
#define	INUSE_BUSY	 0x80	/* Node is busy (high loadave)		*/
#define INUSE_UNKNOWN	 0x100	/* Node has not been heard from yet	*/
#define INUSE_NEEDS_HELLO_PING	0x200	/* Fresh hello sequence needs to be initiated */
#define INUSE_INIT	 0x400	/* Node getting vnode map info		*/
#define INUSE_PROV	 0x800	/* Node is being provisioned		*/
#define INUSE_WAIT_PROV	 0x1000	/* Node is being provisioned		*/
/* INUSE_WAIT_PROV is 0x1000 - this should not clash with MOM_STATE_BUSYKB
 * since INUSE_WAIT_PROV is used as part of the node_state and MOM_STATE_BUSYKB
 * is used inside mom for variable internal_state
 */
#define INUSE_RESVEXCL	0x2000	/* Node is exclusive to a reservation	*/
#define INUSE_OFFLINE_BY_MOM 0x4000 /* Node is offlined by mom */
#define INUSE_MARKEDDOWN 0x8000 /* TPP layer marked node down */
#define INUSE_NEED_ADDRS	0x10000	/* Needs to be sent IP addrs */
#define INUSE_MAINTENANCE	0x20000 /* Node has a job in the admin suspended state */
#define INUSE_SLEEP             0x40000 /* Node is sleeping */
#define INUSE_NEED_CREDENTIALS	0x80000 /* Needs to be sent credentials */

#define VNODE_AVAILABLE (INUSE_FREE | INUSE_JOB | INUSE_JOBEXCL | \
			 INUSE_RESVEXCL | INUSE_BUSY)
#define VNODE_UNAVAILABLE (INUSE_STALE | INUSE_OFFLINE | INUSE_DOWN | \
			   INUSE_DELETED | INUSE_UNKNOWN | INUSE_UNRESOLVABLE \
			   | INUSE_OFFLINE_BY_MOM | INUSE_MAINTENANCE | INUSE_SLEEP)

/* the following are used in Mom's internal state			*/
#define MOM_STATE_DOWN	 INUSE_DOWN
#define MOM_STATE_BUSY	 INUSE_BUSY
#define MOM_STATE_BUSYKB      0x1000	/* keyboard is busy 		   */
#define MOM_STATE_INBYKB      0x2000	/* initial period of keyboard busy */
#define MOM_STATE_CONF_HARVEST  0x4000	/* MOM configured to cycle-harvest */
#define MOM_STATE_MASK	      0x0fff	/* to mask what is sent to server  */

#define	FLAG_OKAY	 0x01	/* "ok" to consider this node in the search */
#define	FLAG_THINKING	 0x02	/* "thinking" to use node to satisfy specif */
#define	FLAG_CONFLICT	 0x04	/* "conflict" temporarily  ~"thinking"      */
#define	FLAG_IGNORE	 0x08	/* "no use"; reality, can't use node in spec*/

/* bits both in nd_state and inuse	*/
#define INUSE_SUBNODE_MASK (INUSE_OFFLINE|INUSE_OFFLINE_BY_MOM|INUSE_DOWN|INUSE_JOB|INUSE_STALE|\
INUSE_JOBEXCL|INUSE_BUSY|INUSE_UNKNOWN|INUSE_INIT|INUSE_PROV|INUSE_WAIT_PROV|\
INUSE_RESVEXCL|INUSE_UNRESOLVABLE|INUSE_MAINTENANCE|INUSE_SLEEP)

#define INUSE_COMMON_MASK  (INUSE_OFFLINE|INUSE_DOWN)
/* state bits that go from node to subn */
#define	CONFLICT	1	/*search process must consider conflicts*/
#define NOCONFLICT	0	/*be oblivious to conflicts in search*/

/* operators to set the state of a vnode. Nd_State_Set is "=",
 * Nd_State_Or is "|=" and Nd_State_And is "&=". This is used in set_vnode_state
 */
enum vnode_state_op {
	Nd_State_Set,
	Nd_State_Or,
	Nd_State_And
};

/* To indicate whether a degraded time should be set on a reservation */
enum vnode_degraded_op {
	Skip_Degraded_Time,
	Set_Degraded_Time,
};


/*
 * NTYPE_* values are used in "node.nd_type"
 */
#define NTYPE_PBS   	 0x00	/* Node is normal node	*/

#define PBSNODE_NTYPE_MASK	0xf		 /* relevant ntype bits */

#define WRITENODE_STATE		0x1		 /*associated w/ offline*/
#define WRITE_NEW_NODESFILE	0x2 /*changed: deleted,ntype,or properties*/

/*
 * To indicate the type of attribute that needs to be updated in the datastore
 */
#define NODE_UPDATE_STATE           0x1  /* state attribute to be updated */
#define NODE_UPDATE_COMMENT         0x2  /* update comment attribute */
#define NODE_UPDATE_OTHERS          0x4  /* other attributes need to be updated */
#define NODE_UPDATE_VNL             0x8  /* this vnode updated in vnl by Mom  */
#define NODE_UPDATE_CURRENT_AOE     0x10  /* current_aoe attribute to be updated */
#define NODE_UPDATE_MOM             0x20 /* update only the mom attribute */


#define NODE_SAVE_FULL  0
#define NODE_SAVE_QUICK 1
#define NODE_SAVE_NEW   2
#define NODE_SAVE_QUICK_STATE 3


/* tree for mapping contact info to node struture */
struct tree {
	unsigned long	   key1;
	unsigned long	   key2;
	mominfo_t         *momp;
	struct tree	  *left, *right;
};

extern struct attribute_def node_attr_def[]; /* node attributes defs */
extern struct pbsnode **pbsndlist;           /* array of ptr to nodes  */
extern int svr_totnodes;                     /* number of nodes (hosts) */
extern struct tree *ipaddrs;
extern struct tree *streams;
extern mominfo_t **mominfo_array;
extern pntPBS_IP_LIST pbs_iplist;
extern int mominfo_array_size;
extern int mom_send_vnode_map;
extern int svr_num_moms;
extern int svr_chngNodesfile;

/* Handlers for vnode state changing.for degraded reservations */
extern	void vnode_unavailable(struct pbsnode *, int);
extern	void vnode_available(struct pbsnode *);
extern	int find_degraded_occurrence(resc_resv *, struct pbsnode *, enum vnode_degraded_op);
extern	int find_vnode_in_execvnode(char *, char *);
extern	void set_vnode_state(struct pbsnode *, unsigned long , enum vnode_state_op);
extern	struct resvinfo *find_vnode_in_resvs(struct pbsnode *, enum vnode_degraded_op);
extern	void free_rinf_list(struct resvinfo *);
extern	void degrade_offlined_nodes_reservations(void);
extern	void degrade_downed_nodes_reservations(void);

extern	int mod_node_ncpus(struct pbsnode *pnode, long ncpus, int actmode);
extern	int	initialize_pbsnode(struct pbsnode*, char*, int);
extern	void	initialize_pbssubn(struct pbsnode *, struct pbssubn*, struct prop*);
extern  struct pbssubn *create_subnode(struct pbsnode *, struct pbssubn *lstsn);
extern	void	effective_node_delete(struct pbsnode*);
extern	void	setup_notification(void);
extern  struct	pbssubn  *find_subnodebyname(char *);
extern	struct	pbsnode  *find_nodebyname(char *);
extern	struct	pbsnode  *find_nodebyaddr(pbs_net_t);
extern	void	free_prop_list(struct prop*);
extern	void	recompute_ntype_cnts(void);
extern	int	process_host_name_part(char*, svrattrl*, char**, int*);
extern  int     create_pbs_node(char *, svrattrl *, int, int *, struct pbsnode **, int);
extern  int     create_pbs_node2(char *, svrattrl *, int, int *, struct pbsnode **, int, int);
extern  int     mgr_set_node_attr(struct pbsnode *, attribute_def *, int, svrattrl *, int, int *, void *, int);
extern	int	node_queue_action(attribute *, void *, int);
extern	int	node_pcpu_action(attribute *, void *, int);
struct prop 	*init_prop(char *pname);
extern	void	set_node_license(void);
extern  int	set_node_topology(attribute*, void*, int);
extern	void	unset_node_license(struct pbsnode *);
extern  mominfo_t *tfind2(const unsigned long, const unsigned long, struct tree **);
extern	int	set_node_host_name(attribute *, void *, int);
extern	int	set_node_hook_action(attribute *, void *, int);
extern  int	set_node_mom_port  (attribute *, void *, int);
extern  mominfo_t *create_mom_entry(char *, unsigned int);
extern  mominfo_t *find_mom_entry(char *, unsigned int);
extern  void	momptr_down(mominfo_t *, char *);
extern  void	momptr_offline_by_mom(mominfo_t *, char *);
extern  void	momptr_clear_offline_by_mom(mominfo_t *, char *);
extern  void	   delete_mom_entry(mominfo_t *);
extern  mominfo_t *create_svrmom_entry(char *, unsigned int, unsigned long *);
extern  void       delete_svrmom_entry(mominfo_t *);
extern  int	legal_vnode_char(char, int);
extern 	char	*parse_node_token(char *, int, int *, char *);
extern  int	cross_link_mom_vnode(struct pbsnode *, mominfo_t *);
extern 	int	fix_indirectness(resource *, struct pbsnode *, int);
extern	int	chk_vnode_pool(attribute *, void *, int);
extern	void	free_pnode(struct pbsnode *);
extern	int	save_nodes_db(int, void *);
extern void	propagate_socket_licensing(mominfo_t *, int);

extern char *msg_daemonname;

#define	NODE_TOPOLOGY_TYPE_HWLOC	"hwloc:"
#define	NODE_TOPOLOGY_TYPE_CRAY		"Cray-v1:"
#define	NODE_TOPOLOGY_TYPE_WIN		"Windows:"

#define	CRAY_COMPUTE	"cray_compute"	/* vntype for a Cray compute node */
#define	CRAY_LOGIN	"cray_login"	/* vntype for a Cray login node */

/* Mom Job defines */
#define JOB_ACT_REQ_REQUEUE 0
#define JOB_ACT_REQ_DELETE  1
#define JOB_ACT_REQ_DEALLOCATE	2


#ifndef PBS_MOM
extern int node_save_db(struct pbsnode *pnode);
extern int add_mom_to_pool(mominfo_t *);
extern void remove_mom_from_pool(mominfo_t *);
extern void reset_pool_inventory_mom(mominfo_t *);
extern vnpool_mom_t *find_vnode_pool(mominfo_t *pmom);
extern int  send_ip_addrs_to_mom(int);
#endif

extern  int	   recover_vmap(void);
extern  void       delete_momvmap_entry(momvmap_t *);
extern  momvmap_t *create_mommap_entry(char *, char *hostn, mominfo_t *, int);
extern struct mominfo   *find_mom_by_vnodename(const char *);
extern momvmap_t        *find_vmap_entry(const char *);
extern mominfo_t *add_mom_data(const char *, void *);
extern mominfo_t	*find_mominfo(const char *);
extern int		create_vmap(void **);
extern void		destroy_vmap(void *);
extern mominfo_t	*find_vmapent_byID(void *, const char *);
extern int		add_vmapent_byID(void *, const char *, void *);

#ifdef	_WORK_TASK_H
extern  void ping_nodes(struct work_task *);
#endif	/* _WORK_TASK_H */
#ifdef	__cplusplus
}
#endif
#endif	/* _PBS_NODES_H */
