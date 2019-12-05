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
#include <errno.h>
#include <assert.h>
#include <stdlib.h>
#include "dis.h"

static pbs_dis_buf_t * dis_get_readbuf(int);
static pbs_dis_buf_t * dis_get_writebuf(int);


/**
 * @brief
 * 	transport_chan_set_before_send - set func to be called before transport send
 *
 * @param[in] fd - file descriptor
 * @param[in] func - func to set as before transport send
 *
 * @return void
 *
 * @par Side Effects:
 *	None
 *
 * @par MT-safe: Yes
 *
 */
void
transport_chan_set_before_send(int fd, void *func)
{
	pbs_tcp_chan_t *chan = transport_get_chan(fd);
	if (chan == NULL)
		return;
	chan->transport_before_send = func;
}

/**
 * @brief
 * 	transport_chan_get_before_send - get func to be called before transport sending data
 *
 * @param[in] fd - file descriptor
 *
 * @return void *
 *
 * @retval !NULL - success
 * @retval NULL - error
 *
 * @par Side Effects:
 *	None
 *
 * @par MT-safe: Yes
 *
 */
void *
transport_chan_get_before_send(int fd)
{
	pbs_tcp_chan_t *chan = transport_get_chan(fd);
	if (chan == NULL)
		return NULL;
	return chan->transport_before_send;
}

/**
 * @brief
 * 	transport_chan_set_after - set func to be called after transport receive data
 *
 * @param[in] fd - file descriptor
 * @param[in] func - func to set as after transport receive
 *
 * @return void
 *
 * @par Side Effects:
 *	None
 *
 * @par MT-safe: Yes
 *
 */
void
transport_chan_set_after_recv(int fd, void *func)
{
	pbs_tcp_chan_t *chan = transport_get_chan(fd);
	if (chan == NULL)
		return;
	chan->transport_after_recv = func;
}

/**
 * @brief
 * 	transport_chan_get_after_recv - get func to be called after transport receiving data
 *
 * @param[in] fd - file descriptor
 *
 * @return void *
 *
 * @retval !NULL - success
 * @retval NULL - error
 *
 * @par Side Effects:
 *	None
 *
 * @par MT-safe: Yes
 *
 */
void *
transport_chan_get_after_recv(int fd)
{
	pbs_tcp_chan_t *chan = transport_get_chan(fd);
	if (chan == NULL)
		return NULL;
	return chan->transport_after_recv;
}

/**
 * @brief
 * 	transport_chan_set_extra - associates optional structure with connection
 *
 * @param[in] fd - file descriptor
 * @param[in] extra - the structure for association
 *
 * @return void
 *
 * @par Side Effects:
 *	None
 *
 * @par MT-safe: Yes
 *
 */
void
transport_chan_set_extra(int fd, void *extra)
{
	pbs_tcp_chan_t *chan = transport_get_chan(fd);
	if (chan == NULL)
		return;
	chan->extra = extra;
}

/**
 * @brief
 * 	transport_chan_get_extra - gets optional structure associated with connection
 *
 * @param[in] fd - file descriptor
 *
 * @return void *
 *
 * @retval !NULL - success
 * @retval NULL - error
 *
 * @par Side Effects:
 *	None
 *
 * @par MT-safe: Yes
 *
 */
void *
transport_chan_get_extra(int fd)
{
	pbs_tcp_chan_t *chan = transport_get_chan(fd);
	if (chan == NULL)
		return NULL;
	return chan->extra;
}

/**
 * @brief
 * 	dis_get_readbuf - get dis read buffer associated with connection
 *
 * @return pbs_dis_but_t *
 *
 * @retval !NULL - success
 * @retval NULL - error
 *
 * @par Side Effects:
 *	None
 *
 * @par MT-safe: Yes
 *
 */
static pbs_dis_buf_t *
dis_get_readbuf(int fd)
{
	pbs_tcp_chan_t *chan = transport_get_chan(fd);
	if (chan == NULL)
		return NULL;
	return &(chan->readbuf);
}

/**
 * @brief
 * 	dis_get_writebuf - get dis write buffer associated with connection
 *
 * @return pbs_dis_but_t *
 *
 * @retval !NULL - success
 * @retval NULL - error
 *
 * @par Side Effects:
 *	None
 *
 * @par MT-safe: Yes
 *
 */
static pbs_dis_buf_t *
dis_get_writebuf(int fd)
{
	pbs_tcp_chan_t *chan = transport_get_chan(fd);
	if (chan == NULL)
		return NULL;
	return &(chan->writebuf);
}

/**
 * @brief
 * 	dis_pack_buf - pack existing data into front of dis buffer
 *
 *	Moves "uncommited" data to front of dis buffer and adjusts counters.
 *	Does a character by character move since data may over lap.
 *
 * @param[in] tp - dis buffer to pack
 *
 * @return void
 *
 * @par Side Effects:
 *	None
 *
 * @par MT-safe: Yes
 *
 */
void
dis_pack_buf(pbs_dis_buf_t *tp)
{
	size_t amt = 0;
	size_t start = 0;
	size_t i = 0;

	start = tp->tdis_trail;
	if (start != 0) {
		amt = tp->tdis_eod - start;
		for (i = 0; i < amt; ++i) {
			*(tp->tdis_thebuf + i) = *(tp->tdis_thebuf + i + start);
		}
		tp->tdis_lead -= start;
		tp->tdis_trail -= start;
		tp->tdis_eod -= start;
	}
}

/**
 * @brief
 * 	dis_resize_buf - resize given dis buffer to appropriate size based on given needed
 *
 * 	if use_lead is true then it will use tdis_lead to calculate new size else tdis_eod
 *
 * @param[in] tp - dis buffer to pack
 * @param[in] needed - min needed buffer size
 * @param[in] use_lead - use tdis_lead or tdis_eod to calculate new size
 *
 * @return int
 *
 * @retval 0 - success
 * @retval -1 - error
 *
 * @par Side Effects:
 *	None
 *
 * @par MT-safe: Yes
 *
 */
int
dis_resize_buf(pbs_dis_buf_t *tp, size_t needed, int use_lead)
{
	size_t len = 0;
	size_t dlen = 0;
	char *tmpcp = NULL;

	if (use_lead)
		dlen = tp->tdis_lead;
	else
		dlen = tp->tdis_eod;
	len = tp->tdis_bufsize - dlen;
	if (needed > len) {
		size_t ru = 0;
		size_t newsz = 0;
		if (use_lead) {
			ru = needed + tp->tdis_lead;
		} else {
			ru = needed + tp->tdis_lead + tp->tdis_eod;
		}
		ru = ru / PBS_DIS_BUFSZ;
		newsz = (ru + 1) * PBS_DIS_BUFSZ;
		tmpcp = (char *) realloc(tp->tdis_thebuf, sizeof(char) * newsz);
		if (tmpcp == NULL) {
			return -1; /* realloc failed */
		} else {
			tp->tdis_thebuf = tmpcp;
			tp->tdis_bufsize = newsz;
		}
	}
	return 0;
}

/**
 * @brief
 * 	dis_clear_buf - reset dis buffer to empty by updating its counter
 *
 *
 * @param[in] tp - dis buffer to clear
 *
 * @return void
 *
 * @par Side Effects:
 *	None
 *
 * @par MT-safe: Yes
 *
 */
void
dis_clear_buf(pbs_dis_buf_t *tp)
{
	tp->tdis_lead = 0;
	tp->tdis_trail = 0;
	tp->tdis_eod = 0;
}

/**
 * @brief
 * 	dis_fill_readbuf - fill read buffer associated with connection with given data
 *
 *
 * @param[in] fd - file descriptor
 * @param[in] data - data to put in read buffer
 * @param[in] len - length of data
 *
 * @return int
 *
 * @retval 0 - success
 * @retval -1 - error
 *
 * @par Side Effects:
 *	None
 *
 * @par MT-safe: Yes
 *
 */
int
dis_fill_readbuf(int fd, char *data, int len)
{
	pbs_dis_buf_t *tp = dis_get_readbuf(fd);

	if (tp == NULL)
		return -1;

	dis_clear_buf(tp);

	if (data == NULL || len == 0)
		return 0;

	dis_resize_buf(tp, len, 0);
	(void)memcpy(&(tp->tdis_thebuf[tp->tdis_eod]), data, len);
	tp->tdis_eod += len;

	return 0;
}

/**
 * @brief
 * 	dis_reset_buf - reset appropriate dis buffer associated with connection
 *
 * @param[in] fd - file descriptor
 * @param[in] rw - reset write buffer if true else read buffer
 *
 * @return void
 *
 * @par Side Effects:
 *	None
 *
 * @par MT-safe: Yes
 *
 */
void
dis_reset_buf(int fd, int rw)
{
	dis_clear_buf((rw == DIS_WRITE_BUF) ? dis_get_writebuf(fd) : dis_get_readbuf(fd));
}

/**
 * @brief
 * 	disr_skip - dis suport routine to skip over data in read buffer
 *
 * @param[in] fd - file descriptor
 * @param[in] ct - count
 *
 * @return	int
 *
 * @retval	number of characters skipped
 *
 * @par Side Effects:
 *	None
 *
 * @par MT-safe: Yes
 *
 */
int
disr_skip(int fd, size_t ct)
{
	pbs_dis_buf_t *tp = dis_get_readbuf(fd);
	if (tp == NULL)
		return 0;
	if (tp->tdis_lead - tp->tdis_eod < ct)
		ct = tp->tdis_lead - tp->tdis_eod;
	tp->tdis_lead += ct;
	return (int)ct;
}

/**
 * @brief
 * 	__transport_read - read data from connection to "fill" the buffer
 *	Update the various buffer pointers.
 *
 * @param[in] fd - socket descriptor
 *
 * @return	int
 *
 * @retval	>0 	number of characters read
 * @retval	0 	if EOD (no data currently avalable)
 * @retval	-1 	if error
 * @retval	-2 	if EOF (stream closed)
 *
 * @par Side Effects:
 *	None
 *
 * @par MT-safe: Yes
 *
 */
int
__transport_read(int fd)
{
	int i;
	int (*after_recv)(int) = transport_chan_get_after_recv(fd);
	pbs_dis_buf_t *tp = dis_get_readbuf(fd);

	if (tp == NULL)
		return -1;
	dis_pack_buf(tp);
	dis_resize_buf(tp, PBS_DIS_BUFSZ, 0);
	i = transport_recv(fd, &(tp->tdis_thebuf[tp->tdis_eod]), tp->tdis_bufsize - tp->tdis_eod);
	if (i > 0) {
		tp->tdis_eod += i;
		if (after_recv != NULL) {
			if (after_recv(fd) == -1) {
				return -1;
			}
		}
	}
	return ((i == 0) ? -2 : i);
}

/**
 * @brief
 * 	dis_getc - dis support routine to get next character from read buffer
 *
 * @param[in] fd - file descriptor
 *
 * @return	int
 *
 * @retval	>0 	number of characters read
 * @retval	-1 	if EOD or error
 * @retval	-2 	if EOF (stream closed)
 *
 * @par Side Effects:
 *	None
 *
 * @par MT-safe: Yes
 *
 */
int
dis_getc(int fd)
{
	int x = 0;
	pbs_dis_buf_t *tp = dis_get_readbuf(fd);

	if (tp == NULL)
		return -1;
	if (tp->tdis_lead >= tp->tdis_eod) {
		/* not enought data, try to get more */
		x = __transport_read(fd);
		if (x <= 0)
			return ((x == -2) ? -2 : -1);	/* Error or EOF */
	}
	return ((int)tp->tdis_thebuf[tp->tdis_lead++]);
}

/**
 * @brief
 * 	dis_gets - dis support routine to get a string from read buffer
 *
 * @param[in] fd - file descriptor
 * @param[in] str - string to be written
 * @param[in] ct - count
 *
 * @return	int
 *
 * @retval	>0 	number of characters read
 * @retval	0 	if EOD (no data currently avalable)
 * @retval	-1 	if error
 * @retval	-2 	if EOF (stream closed)
 *
 * @par Side Effects:
 *	None
 *
 * @par MT-safe: Yes
 *
 */
int
dis_gets(int fd, char *str, size_t ct)
{
	int x = 0;
	pbs_dis_buf_t *tp = dis_get_readbuf(fd);

	if (tp == NULL) {
		*str = '\0';
		return -1;
	}
	while (tp->tdis_eod - tp->tdis_lead < ct) {
		/* not enought data, try to get more */
		x = __transport_read(fd);
		if (x <= 0)
			return x;	/* Error or EOF */
	}
	(void)memcpy(str, &tp->tdis_thebuf[tp->tdis_lead], ct);
	tp->tdis_lead += ct;
	return (int)ct;
}

/**
 * @brief
 * 	dis_puts - dis support routine to put a counted string of characters
 *	into the write buffer.
 *
 * @param[in] fd - file descriptor
 * @param[in] str - string to be written
 * @param[in] ct - count
 *
 * @return	int
 *
 * @retval	>= 0	the number of characters placed
 * @retval	-1 	if error
 *
 * @par Side Effects:
 *	None
 *
 * @par MT-safe: Yes
 *
 */
int
dis_puts(int fd, const char *str, size_t ct)
{
	pbs_dis_buf_t *tp = dis_get_writebuf(fd);
	if (tp == NULL)
		return -1;
	if (dis_resize_buf(tp, ct, 1) != 0)
		return -1;
	(void)memcpy(&tp->tdis_thebuf[tp->tdis_lead], str, ct);
	tp->tdis_lead += ct;
	return ct;
}

/**
 * @brief
 * 	disr_commit - dis support routine to commit/uncommit read data
 *
 * @param[in] fd - file descriptor
 * @param[in] commit_flag - indication for commit or uncommit
 *
 * @return int
 *
 * @retval 0 - success
 * @retval -1 - error
 *
 * @par Side Effects:
 *	None
 *
 * @par MT-safe: Yes
 *
 */
int
disr_commit(int fd, int commit_flag)
{
	pbs_dis_buf_t *tp = dis_get_readbuf(fd);
	if (tp == NULL)
		return -1;
	if (commit_flag) {
		/* commit by moving trailing up */
		tp->tdis_trail = tp->tdis_lead;
	} else {
		/* uncommit by moving leading back */
		tp->tdis_lead = tp->tdis_trail;
	}
	return 0;
}

/**
 * @brief
 * 	disw_commit - dis support routine to commit/uncommit write data
 *
 * @param[in] fd - file descriptor
 * @param[in] commit_flag - indication for commit or uncommit
 *
 * @return int
 *
 * @retval 0 - success
 * @retval -1 - error
 *
 * @par Side Effects:
 *	None
 *
 * @par MT-safe: Yes
 *
 */
int
disw_commit(int fd, int commit_flag)
{
	pbs_dis_buf_t *tp = dis_get_writebuf(fd);
	if (tp == NULL)
		return -1;
	if (commit_flag) {
		/* commit by moving trailing up */
		tp->tdis_trail = tp->tdis_lead;
	} else {
		/* uncommit by moving leading back */
		tp->tdis_lead = tp->tdis_trail;
	}
	return 0;
}

/**
 * @brief
 *	flush dis write buffer
 *
 *	Writes "committed" data in buffer to file descriptor,
 *	packs remaining data (if any), resets pointers
 *
 * @param[in] - fd - file descriptor
 *
 * @return int
 *
 * @retval  0 on success
 * @retval -1 on error
 *
 * @par Side Effects:
 *	None
 *
 * @par MT-safe: Yes
 *
 */
int
dis_flush(int fd)
{
	int (*before_send)(int, void *, int) = transport_chan_get_before_send(fd);
	pbs_dis_buf_t *tp = dis_get_writebuf(fd);

	if (tp == NULL)
		return -1;
	if (tp->tdis_trail == 0)
		return 0;
	if (before_send != NULL) {
		if (before_send(fd, tp->tdis_thebuf, tp->tdis_trail) == -1)
			return -1;
		if (tp->tdis_trail == 0)
			return 0;
	}
	if (transport_send(fd, tp->tdis_thebuf, tp->tdis_trail) == -1) {
		return (-1);
	}
	tp->tdis_eod = tp->tdis_lead;
	dis_pack_buf(tp);
	return 0;
}

/**
 * @brief
 * 	dis_destroy_chan - release structures associated with fd
 *
 * @param[in] fd - socket descriptor
 *
 * @return void
 *
 * @par Side Effects:
 *	None
 *
 * @par MT-safe: Yes
 *
 */
void
dis_destroy_chan(int fd)
{
	pbs_tcp_chan_t *chan = transport_get_chan(fd);
	if (chan != NULL) {
		if (chan->readbuf.tdis_thebuf) {
			free(chan->readbuf.tdis_thebuf);
			chan->readbuf.tdis_thebuf = NULL;
		}
		if (chan->writebuf.tdis_thebuf) {
			free(chan->writebuf.tdis_thebuf);
			chan->writebuf.tdis_thebuf = NULL;
		}
		dis_clear_buf(&(chan->readbuf));
		dis_clear_buf(&(chan->writebuf));
		free(chan);
		transport_set_chan(fd, NULL);
	}
}


/**
 * @brief
 *	allocate dis buffers associated with connection, if already allocated then clear it
 *
 * @param[in] fd - file descriptor
 *
 * @return void
 *
 * @par Side Effects:
 *	None
 *
 * @par MT-safe: Yes
 *
 */
void
dis_setup_chan(int fd, pbs_tcp_chan_t * (*inner_transport_get_chan)(int))
{
	pbs_tcp_chan_t *chan;
	int rc;

	/* check for bad file descriptor */
	if (fd < 0)
		return;
	chan = (pbs_tcp_chan_t *)(*inner_transport_get_chan)(fd);
	if (chan == NULL) {
		if (errno == ENOTCONN)
			return;
		chan = (pbs_tcp_chan_t *) calloc(1, sizeof(pbs_tcp_chan_t));
		assert(chan != NULL);
		chan->readbuf.tdis_thebuf = calloc(1, PBS_DIS_BUFSZ);
		assert(chan->readbuf.tdis_thebuf != NULL);
		chan->readbuf.tdis_bufsize = PBS_DIS_BUFSZ;
		chan->writebuf.tdis_thebuf = calloc(1, PBS_DIS_BUFSZ);
		assert(chan->writebuf.tdis_thebuf != NULL);
		chan->writebuf.tdis_bufsize = PBS_DIS_BUFSZ;
		rc = transport_set_chan(fd, chan);
		assert(rc == 0);
	}

	/* initialize read and write buffers */
	dis_clear_buf(&(chan->readbuf));
	dis_clear_buf(&(chan->writebuf));
}
