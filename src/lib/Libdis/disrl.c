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
 * @file	disrl.c
 *
 * @par Synopsis:
 * 	long double disrl(int stream, int *retval)
 *
 *	Gets a Data-is-Strings floating point number from <stream> and converts
 *	it into a long double and returns it.  The number from <stream> consists
 *	of two consecutive signed integers.  The first is the coefficient, with
 *	its implied decimal point at the low-order end.  The second is the
 *	exponent as a power of 10.
 *
 *	*<retval> gets DIS_SUCCESS if everything works well.  It gets an error
 *	code otherwise.  In case of an error, the <stream> character pointer is
 *	reset, making it possible to retry with some other conversion strategy.
 *
 *	By fiat of the author, neither loss of significance nor underflow are
 *	errors.
 */

#include <pbs_config.h>   /* the master config generated by configure */

#include <assert.h>
#include <math.h>
#include <stddef.h>
#include <stdio.h>

#include "dis.h"
#include "dis_.h"

/**
 * @brief
 *      Gets a Data-is-Strings floating point number from <stream> and converts
 *      it into a long double which it returns.  The number from <stream> consists of
 *      two consecutive signed integers.  The first is the coefficient, with its
 *      implied decimal point at the low-order end.  The second is the exponent
 *      as a power of 10.
 *
 * @param[in] stream - socket descriptor
 * @param[out] retval - success/error code
 *
 * @return      dis_long_double_t
 * @retval      long double value	success
 * @retval      0.0L             	error
 *
 */

dis_long_double_t
disrl(int stream, int *retval)
{
	int		expon;
	unsigned	uexpon;
	int		locret;
	int		negate;
	unsigned	ndigs;
	unsigned	nskips;
	dis_long_double_t 	ldval;

	assert(retval != NULL);

	ldval = 0.0L;
	locret = disrl_(stream, &ldval, &ndigs, &nskips, LDBL_DIG, 1, 0);
	if (locret == DIS_SUCCESS) {
		locret = disrsi_(stream, &negate, &uexpon, 1, 0);
		if (locret == DIS_SUCCESS) {
			expon = negate ? nskips - uexpon : nskips + uexpon;
			if (expon + (int)ndigs > LDBL_MAX_10_EXP) {
				if (expon + (int)ndigs > LDBL_MAX_10_EXP + 1) {
					ldval = ldval < 0.0L ?
						-HUGE_VAL : HUGE_VAL;
					locret = DIS_OVERFLOW;
				} else {
					ldval *= disp10l_(expon - 1);
					if (ldval > LDBL_MAX / 10.0L) {
						ldval = ldval < 0.0L ?
							-HUGE_VAL : HUGE_VAL;
						locret = DIS_OVERFLOW;
					} else
						ldval *= 10.0L;
				}
			} else {
				if (expon < LDBL_MIN_10_EXP) {
					ldval *= disp10l_(expon + (int)ndigs);
					ldval /= disp10l_((int)ndigs);
				} else
					ldval *= disp10l_(expon);
			}
		}
	}
	if (disr_commit(stream, locret == DIS_SUCCESS) < 0)
		locret = DIS_NOCOMMIT;
	*retval = locret;
	return (ldval);
}
