/*
 * Copyright (C) 1994-2016 Altair Engineering, Inc.
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
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU Affero General Public License for more details.
 *  
 * You should have received a copy of the GNU Affero General Public License along 
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 *  
 * Commercial License Information: 
 * 
 * The PBS Pro software is licensed under the terms of the GNU Affero General 
 * Public License agreement ("AGPL"), except where a separate commercial license 
 * agreement for PBS Pro version 14 or later has been executed in writing with Altair.
 *  
 * Altair’s dual-license business model allows companies, individuals, and
 * organizations to create proprietary derivative works of PBS Pro and distribute
 * them - whether embedded or bundled with other software - under a commercial
 * license agreement.
 *
 * Use of Altair’s trademarks, including but not limited to "PBS™",
 * "PBS Professional®", and "PBS Pro™" and Altair’s logos is subject to Altair's
 * trademark licensing policies.
 *
 */

#include <windows.h>
#include <stdio.h>
#include <process.h>
#include <windef.h>
#include <lm.h>
#ifndef SECURITY_WIN32
#define SECURITY_WIN32 1
#endif
#include <security.h>
#include <wincred.h>
#include <userenv.h>
#include <winnt.h>
#include <ntsecapi.h>

#pragma warning(disable:4996) /* disable CRT secure warning */

#define PIPE_MAX_WAITTIME		60000
#define INTERACT_STDOUT         "ptl_interact_stdout_"
#define INTERACT_STDIN          "ptl_interact_stdin_"
#define INTERACT_STDERR         "ptl_interact_stderr_"
#define INTERACT_CMD			"ptl_interact_cmd"
#define READBUF_SIZE 8192 /* Size of pipe read buffer */
#define CONSOLE_BUFSIZE 2048 /* Size of Console input buffer */
#define PIPENAME_MAX_LENGTH     256 /* Maximum length of pipe name */
#define CMDLINE_LENGTH 4096

#ifndef HAVE_SNPRINTF
#define HAVE_SNPRINTF 1
#endif
#define snprintf	_snprintf

int
main(int argc, char *argv[])
{
    char myid[PIPENAME_MAX_LENGTH] = {'\0'};
	char cmd_pipename[PIPENAME_MAX_LENGTH] = {0};
	char err_msg[BUFSIZ] = {'\0'};
	char *perr_msg = NULL;
	HANDLE hCmdPipe = INVALID_HANDLE_VALUE;
	char *remote_hostname = "mark1";
	int len = DNLEN+UNLEN+1;
	char dn[DNLEN+UNLEN+1] = {'\0'};
	char username[UNLEN+1] = {'\0'};
	char domain[DNLEN+1] = {'\0'};
	CREDENTIAL *cred = NULL;
	char *password = NULL;
	int password_len = 0;
	char *p = NULL;
	int i = 1;

	if (argc <= 1) {
		perr_msg = "Option require!\n";
		goto end;
	}
	if (!GetUserNameEx(NameSamCompatible, dn, &len)) {
		perr_msg = "Failed to find current username\n";
		goto end;
	}
	p = strchr(dn, (int)'\\');
	if (p == NULL) {
		perr_msg = "Failed to find current domain name\n";
		goto end;
	} else {
		*p = '\0';
		strncpy_s(domain, DNLEN, dn, strlen(dn));
		strncpy_s(username, UNLEN, p+1, strlen(p+1));
	}

	while (i < argc) {
		if (!strncmp(argv[i], "-u", 2) || !strncmp(argv[i], "--user", 6)) {
			strncpy(username, argv[i+1], sizeof(username)-1);
			i += 2;
		} else if (!strncmp(argv[i], "--", 2)) {
			i++;
			break;
		} else {
			break;
		}
	}
	len = argc - i;
	if (len == 0) {
		perr_msg = "No command specified!\n";
		goto end;
	}
	memset(dn, 0, sizeof(dn));
	p = strchr(username, (int)'\\');
	if (p != NULL) {
		strncpy(dn, username, sizeof(dn)-1);
		*p = '\0';
		strncpy_s(domain, DNLEN, username, strlen(dn));
		strncpy_s(username, UNLEN, p+1, strlen(p+1));
	} else {
		snprintf(dn, sizeof(dn)-1, "%s\\%s", domain, username);
	}
	if (!CredRead(dn, 1, 0, &cred)) {
		perr_msg = "Failed to find user's password\n";
		goto end;
	}

	password_len = cred->CredentialBlobSize;
	password = (char *)malloc(password_len);
	memset(password, 0, password_len);
	wcstombs(password, (const wchar_t *)cred->CredentialBlob, password_len);
	password[password_len-1] = '\0';
	CredFree(&cred);
	memset(cred, 0, sizeof(CREDENTIAL));

	if (!connect_remote_resource(remote_hostname, "IPC$", TRUE)) {
		sprintf(err_msg, "Couldn't connect to %s\n", remote_hostname);
		perr_msg = err_msg;
		goto end;
	}
	snprintf(cmd_pipename, PIPENAME_MAX_LENGTH - 1, "\\\\%s\\pipe\\%ssvr", remote_hostname, INTERACT_CMD);
	hCmdPipe = do_WaitNamedPipe(cmd_pipename, PIPE_MAX_WAITTIME, GENERIC_READ);
	if (hCmdPipe == INVALID_HANDLE_VALUE) {
		perr_msg = "Failed to retrive client id\n";
		goto end;
	}
	if(recv_string(hCmdPipe, myid) == -1) {
		perr_msg = "Failed to retrive client id\n";
		goto end;
	}
	disconnect_close_pipe(&(hCmdPipe));
	snprintf(cmd_pipename, PIPENAME_MAX_LENGTH - 1, "\\\\%s\\pipe\\%s%s", remote_hostname, INTERACT_CMD, myid);
	hCmdPipe = do_WaitNamedPipe(cmd_pipename, PIPE_MAX_WAITTIME, GENERIC_WRITE|GENERIC_READ);
	if (hCmdPipe == INVALID_HANDLE_VALUE) {
		perr_msg = "Failed to connect remote server\n";
		goto end;
	}
	if (send_string(hCmdPipe, domain) == -1) {
		perr_msg = "failed to send domain to remote server\n";
		goto end;
	}
	if (send_string(hCmdPipe, username) == -1) {
		perr_msg = "failed to send domain to remote server\n";
		goto end;
	}
	if (send_string(hCmdPipe, password) == -1) {
		perr_msg = "failed to send domain to remote server\n";
		goto end;
	}
	memset(password, 0, password_len);
	if (send_string(hCmdPipe, (char *)&len) == -1) {
		perr_msg = "failed to send cmdline len to remote server\n";
		goto end;
	}
	while (i < argc) {
		if (send_string(hCmdPipe, argv[i]) == -1) {
			perr_msg = "failed to send cmdline to remote server\n";
			goto end;
		}
		i++;
	}
	err_msg[0] = 'p';
	if(recv_string(hCmdPipe, err_msg) == -1) {
		perr_msg = "failed to retrive ack from server\n";
		goto end;
	}
	if (strlen(err_msg) != 0) {
		perr_msg = err_msg;
		goto end;
	}
	disconnect_close_pipe(&(hCmdPipe));
	if(execute_remote_shell_command(remote_hostname, myid, 1) == FALSE) {
		fprintf(stderr, "Couldn't execute remote shell at host %s\n", remote_hostname);
		return -1;
	}
end:
	CredFree(&cred);
	if (cred != NULL) {
		memset(cred, 0, sizeof(CREDENTIAL));
	}
	memset(password, 0, password_len);
	disconnect_close_pipe(&(hCmdPipe));
	connect_remote_resource(remote_hostname, "IPC$", FALSE);
	if (perr_msg != NULL) {
		fprintf(stderr, "%s", perr_msg);
		exit (1);
	} else {
		exit(0);
	}
}
