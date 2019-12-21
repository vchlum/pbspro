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
 * @file	rpp.c
 * @brief
 *	Routines to communicate with UDP packets - Reliable Packet Protocol.
 *
 *	This package provides for sending information in "messages"
 *	which are complete blocks of data which will either arrive
 *	complete or not at all.
 */
#include	"tpp.h"


/* definitions of pointer functions for global use */
void 					(*pfn_rpp_add_close_func)(int, void (*func)(int));

/*
 *	Global Variables
 */
int	rpp_dbprt = 0;				/* controls debug printing */

/**
 *	Current file descriptor.  Any call to tpp_open will use this
 *	for the returned stream.
 */
int		tpp_fd = -1;

/**
 *	Number of retrys to for each packet.
 */
int		rpp_retry = RPP_RETRY;

/**
 *	Number of packets to send before gettin an ACK.
 */
int		rpp_highwater = RPP_HIGHWATER;
