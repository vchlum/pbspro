
#
# Copyright (C) 1994-2019 Altair Engineering, Inc.
# For more information, contact Altair at www.altair.com.
#
# This file is part of the PBS Professional ("PBS Pro") software.
#
# Open Source License Information:
#
# PBS Pro is free software. You can redistribute it and/or modify it under the
# terms of the GNU Affero General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# PBS Pro is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.
# See the GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Commercial License Information:
#
# For a copy of the commercial license terms and conditions,
# go to: (http://www.pbspro.com/UserArea/agreement.html)
# or contact the Altair Legal Department.
#
# Altair’s dual-license business model allows companies, individuals, and
# organizations to create proprietary derivative works of PBS Pro and
# distribute them - whether embedded or bundled with other software -
# under a commercial license agreement.
#
# Use of Altair’s trademarks, including but not limited to "PBS™",
# "PBS Professional®", and "PBS Pro™" and Altair’s logos is subject to Altair's
# trademark licensing policies.
#

AC_DEFUN([PBS_AC_WITH_SENDMAIL],
[
  AC_ARG_WITH([sendmail],
    AS_HELP_STRING([--with-sendmail=EXECUTABLE],
      [Specify the full path where the sendmail executable is installed.]
    )
  )
  AS_IF([test "x$with_sendmail" != "x"],
    sendmail_cmd=["$with_sendmail"],
    sendmail_cmd=["/usr/sbin/sendmail"]
  )
  AC_MSG_CHECKING([for sendmail])
  AC_MSG_RESULT([$sendmail_cmd])
  AC_DEFINE_UNQUOTED([SENDMAIL_CMD], ["$sendmail_cmd"], [Full path to the sendmail executable])
])

