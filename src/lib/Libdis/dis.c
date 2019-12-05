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
#include <pbs_config.h>   /* the master config generated by configure */

#include "dis_.h"

const char *dis_emsg[] = {"No error",
	"Input value too large to convert to this type",
	"Tried to write floating point infinity",
	"Negative sign on an unsigned datum",
	"Input count or value has leading zero",
	"Non-digit found where a digit was expected",
	"Input string has an embedded ASCII NUL",
	"Premature end of message",
	"Unable to malloc enough space for string",
	"Supporting protocol failure",
	"Protocol failure in commit",
	"End of File"};

/* this is for our client threading functionlity to get the DIS_BUFSZ */
long dis_buffsize = DIS_BUFSIZ;

/**
 * @brief
 * 	called once per process to initialize the dis tables
 *
 */

void
dis_init_tables(void)
{
	if (dis_dmx10 == 0)
		disi10d_();
	if (dis_lmx10 == 0)
		disi10l_();
	if (dis_umaxd == 0)
		disiui_();
	init_ulmax();
}
