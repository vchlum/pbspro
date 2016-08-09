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

#define DESKTOP_ALL	(DESKTOP_CREATEMENU | DESKTOP_CREATEWINDOW  | \
						DESKTOP_ENUMERATE | DESKTOP_HOOKCONTROL | \
						DESKTOP_JOURNALPLAYBACK | DESKTOP_JOURNALRECORD | \
						DESKTOP_READOBJECTS | DESKTOP_SWITCHDESKTOP | \
						DESKTOP_WRITEOBJECTS | DELETE | \
						READ_CONTROL | WRITE_DAC | WRITE_OWNER )

void WINAPI PTLServerMain(DWORD dwArgc, LPTSTR *rgszArgv);
void WINAPI PTLServerHandler(DWORD dwControl);
DWORD WINAPI main_thread(void *pv);

const TCHAR* const g_PTLServerName = __TEXT("PTL_RS");
HANDLE g_hthreadMain = 0;
SERVICE_STATUS_HANDLE g_ssHandle = 0;
DWORD g_dwCurrentState = SERVICE_START_PENDING;
HANDLE	hStop = NULL;
SERVICE_STATUS ss;
int quit = 0;

/**
 * @brief
 *	Send data of bufsize length to the peer. Used for communications
 * 	between the foreground and background qsub processes.
 *
 * @param[in]	s - pointer to the windows PIPE or Unix domain socket
 * @param[in]	buf - The buf to send data from
 * @param[in]	bufsize - The amount of data to send
 *
 * @return      int
 * @retval	-1 - Failure
 * @retval	 0 - Success
 *
 */
int
dosend(void *s, char *buf, int bufsize)
{
	int bytes = 0;
	BOOL fSuccess = 0;
	HANDLE hPipe = (HANDLE) s;

	fSuccess = WriteFile(
		hPipe, // handle to pipe
		buf, // buffer to write from
		bufsize, // number of bytes to write
		(DWORD *)&bytes, // number of bytes written
		NULL); // not overlapped I/O

	if (!fSuccess || bufsize != bytes)
		return -1;
	return 0;
}

/**
 * @brief
 *	Receive data of bufsize length from the peer. Used for communications
 * 	between the foreground and background qsub processes.
 *
 * @param[in]	s - pointer to the windows PIPE or Unix domain socket
 * @param[in]	buf - The buf to receive data into
 * @param[in]	bufsize - The amount of data to read
 *
 * @return      int
 * @retval	-1 - Failure
 * @retval	 0 - Success
 *
 */
int
dorecv(void *s, char *buf, int bufsize)
{
	int bytes = 0;
	char *p = buf;
	int remaining = bufsize;
	BOOL fSuccess = 0;
	HANDLE hPipe = (HANDLE) s;

	do {
		fSuccess = ReadFile(
			hPipe, // handle to pipe
			p, // buffer to receive data
			remaining, // size of buffer
			(DWORD *)&bytes, // number of bytes read
			NULL); // not overlapped I/O

		if (!fSuccess && GetLastError() != ERROR_MORE_DATA)
			return -1;
		p += bytes;
		remaining -= bytes;
	} while (!fSuccess); // repeat loop if ERROR_MORE_DATA
	return 0;
}

/**
 * @brief
 *  	Send a null terminated string to the peer process. Used by backrgound and
 * 	foreground qsub processes to communicate error-strings, job-ids etc.
 *
 * @param[in]	s - pointer to the windows PIPE or Unix domain socket
 * @parma[in]	str - null terminated string to send
 *
 * @return      int
 * @retval	-1 - Failure
 * @retval	 0 - Success
 *
 */
int
send_string(void *s, char *str)
{
	int len = strlen(str) + 1;

	if ((dosend(s, (char *) &len, sizeof(int)) != 0) ||
		(dosend(s, str, len) != 0))
		return -1;

	return 0;
}

/**
 * @brief
 *  	Recv a null terminated string from the peer process. Used by backrgound and
 * 	foreground qsub processes to communicate error-strings, job-ids etc.
 *
 * @param[in]	s - pointer to the windows PIPE or Unix domain socket
 * @parma[in]	str - null terminated string to send
 *
 * @return      int
 * @retval	-1 - Failure
 * @retval	 0 - Success
 *
 */
int
recv_string(void *s, char *str)
{
	int len = 0;

	if ((dorecv(s, (char *) &len, sizeof(int)) != 0) ||
		(dorecv(s, str, len) != 0))
		return -1;

	return 0;
}

void get_error_msg(char *buf, size_t size)
{
	LPVOID	lpMsgBuf;
	int	err = GetLastError();

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, err,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf, 0, NULL);
	memset(buf, 0, size);
	strncpy(buf, lpMsgBuf, size);
	LocalFree(lpMsgBuf);
	buf[size-1] = '\0';
}

void
ErrorMessage(char *str)
{
	char buf[4096];
	get_error_msg(buf, sizeof(buf)-1);
	fprintf(stderr, "%s: %s", str, buf);
	exit(1);
}

/**
* @ brief Close a valid handle
*
* @param[in] p_handle : pointer to a Windows HANDLE
*
* @returns void
*/
void
close_valid_handle(HANDLE *p_handle)
{
	if (p_handle == NULL)
		return;
	if (*p_handle != INVALID_HANDLE_VALUE && *p_handle != NULL)
		CloseHandle(*p_handle);
	*p_handle = INVALID_HANDLE_VALUE;
}

/**
* @brief
*	Disconnect the named pipe and close it's handle.
*
* @param[in] hpipe - handle to the named pipe.
*
* @return  void
*
*/
void
disconnect_close_pipe(HANDLE *hpipe)
{
	if (*hpipe == NULL)
		return;
	if (*hpipe != INVALID_HANDLE_VALUE) {
		DisconnectNamedPipe(*hpipe);
		close_valid_handle(hpipe);
	}
}

DWORD create_pipe(DWORD type, char *name, HANDLE *pipe)
{
	SECURITY_ATTRIBUTES SecAttrib = {0};
	SECURITY_DESCRIPTOR SecDesc;

	*pipe = INVALID_HANDLE_VALUE;
	if (!((type == PIPE_ACCESS_DUPLEX) || (type == PIPE_ACCESS_INBOUND) || (type == PIPE_ACCESS_OUTBOUND)))
		return 1;

	if (name == NULL)
		return 1;

	if (InitializeSecurityDescriptor(&SecDesc, SECURITY_DESCRIPTOR_REVISION) == 0) {
		return GetLastError();
	}
	if (SetSecurityDescriptorDacl(&SecDesc, TRUE, NULL, FALSE) == 0) {
		return GetLastError();
	}
	SecAttrib.nLength = sizeof(SECURITY_ATTRIBUTES);
	SecAttrib.lpSecurityDescriptor = &SecDesc;;
	SecAttrib.bInheritHandle = TRUE;
	*pipe = CreateNamedPipe(name, type, PIPE_TYPE_MESSAGE| PIPE_TYPE_BYTE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 0, 0, (DWORD)-1, &SecAttrib);
	if (*pipe == INVALID_HANDLE_VALUE) {
		return GetLastError();
	}
	return 0;
}

/**
* @brief
*	Create pipes at local host to redirect a process's standard input, output and error.
*  If pipe creation fails for any of the required standard pipes, return error.
*
* @param[in/out]	psi - Pointer to STARTUPINFO corresponding to the process
*			      whose standard input, output and error handles need to be redirected.
* @param[in] pipename_append - Appendix to the pipename.
* @param[in] is_interactive - Should process's stdin be redirected? redirect stdin if non-zero.
*
* @return  int
* @retval	0 - no error
* @retval	!0 - error number, describing error while trying to create std pipes
*
*/
int
create_std_pipes(STARTUPINFO* psi, char *pipename_append, int is_interactive)
{
	char stdoutpipe[PIPENAME_MAX_LENGTH] = "";
	char stderrpipe[PIPENAME_MAX_LENGTH] = "";
	char stdinpipe[PIPENAME_MAX_LENGTH] = "";
	int err = 0;

	if (psi == NULL || pipename_append == NULL)
		return -1;

	/* Use Process's standard input/output/error handles */
	psi->dwFlags |= STARTF_USESTDHANDLES ;
	psi->hStdOutput = INVALID_HANDLE_VALUE;
	psi->hStdInput = INVALID_HANDLE_VALUE;
	psi->hStdError = INVALID_HANDLE_VALUE;

	/* stdout pipe name */
	snprintf(stdoutpipe,
		PIPENAME_MAX_LENGTH - 1,
		"\\\\.\\pipe\\%s%s",
		INTERACT_STDOUT,
		pipename_append);
	/* Create stdout pipe.
	* This pipe needs an outbound access e.g. this end of pipe can
	* "only write"(GENERIC_WRITE) and client on the other end can "only
	* read"(GENERIC_READ).
	* Enable blocking mode using PIPE_WAIT, so that any subsequent ConnectNamedPipe()
	* call, waits indefinitely for a client to connect to this pipe.
	*/
	err = create_pipe(PIPE_ACCESS_OUTBOUND, stdoutpipe, &(psi->hStdOutput));
	if ((err != 0) || (psi->hStdOutput == INVALID_HANDLE_VALUE))
		return err;

	/* stderr pipe name */
	snprintf(stderrpipe,
		PIPENAME_MAX_LENGTH - 1,
		"\\\\.\\pipe\\%s%s",
		INTERACT_STDERR,
		pipename_append);
	/* Create stderr pipe.
	* This pipe needs an outbound access e.g. this end of pipe can
	* "only write"(GENERIC_WRITE) and client on the other end can "only
	* read"(GENERIC_READ).
	* Enable blocking mode using PIPE_WAIT, so that any subsequent ConnectNamedPipe()
	* call, waits indefinitely for a client to connect to this pipe.
	*/
	err = create_pipe(PIPE_ACCESS_OUTBOUND, stderrpipe, &(psi->hStdError));
	if ((err != 0) || (psi->hStdError == INVALID_HANDLE_VALUE)) {
		close_valid_handle(&(psi->hStdOutput));
		return err;
	}

	/* Create stdin pipe if it is an interactive process */
	if (is_interactive) {
		/* stdin pipe name */
		snprintf(stdinpipe,
			PIPENAME_MAX_LENGTH - 1,
			"\\\\.\\pipe\\%s%s",
			INTERACT_STDIN,
			pipename_append);
		/* Create stdin pipe.
		* This pipe needs an inbound access e.g. this end of pipe can
		* "only read"(GENERIC_READ) and client on the other end can "only
		* write"(GENERIC_WRITE).
		* Enable blocking mode using PIPE_WAIT, so that any subsequent ConnectNamedPipe()
		* call, waits indefinitely for a client to connect to this pipe.
		*/
		err = create_pipe(PIPE_ACCESS_INBOUND, stdinpipe, &(psi->hStdInput));
		if ((err != 0) || (psi->hStdInput == INVALID_HANDLE_VALUE)) {
			close_valid_handle(&(psi->hStdOutput));
			close_valid_handle(&(psi->hStdError));
			return err;
		}
	}
	return 0;
}

/**
* @brief
*	Connect to the named pipe, avoiding connection race that
*  can occur if the named pipe client connects between CreateNamedPipe() and ConnectNamedPipe()
*  calls. ConnectNamedPipe() in this case fails with error ERROR_PIPE_CONNECTED.
*  We need to ignore this error at named pipe server after calling ConnectNamedPipe().
*
*
* @param[in]	hPipe - Handle to the named pipe.
* @param[in]   pOverlapped - A pointer to an OVERLAPPED structure.
*
* @return  int
* @retval	0 - success
* @retval	!0 - error number, while trying to connect named pipe
*
*/
int
do_ConnectNamedPipe(HANDLE hPipe, LPOVERLAPPED pOverlapped)
{
	int err = 0;
	/* A client can connect between CreateNamedPipe and ConnectNamedPipe
	* calls, in this case ConnectNamedPipe() call will return failure(0) with
	* error ERROR_PIPE_CONNECTED, ignore this error.
	*/
	if (ConnectNamedPipe(hPipe, pOverlapped) == 0) {
		err = GetLastError();
		if (err != ERROR_PIPE_CONNECTED)
			return err;
	}
	return 0;
}

/**
* @brief
*	Connect to pipes that redirect a process's stdin, stdout, stderr.
*
*
* @param[in]	psi - Pointer to STARTUPINFO corresponding to the process
*		      whose standard input, output and error handles are redirected to named pipes.
* @param[in]   is_interactive - Is process's stdin being redirected? Connect to stdin pipe, if non-zero.
*
* @return  	int
* @retval	0 - success
* @retval	!0 && > 0 - error number, while trying to connect std pipes
* @retval	-1 - invalid arguments
*
*/
int
connectstdpipes(STARTUPINFO* psi, int is_interactive)
{
	int err = 0;

	if (psi == NULL)
		return -1;

	/* Waiting for client to connect to stdout pipe */
	if ((err = do_ConnectNamedPipe(psi->hStdOutput, NULL)) != 0) {
		return err;
	}
	if (is_interactive) {
		/* Waiting for client to connect to stdin pipe */
		if ((err = do_ConnectNamedPipe(psi->hStdInput, NULL)) != 0) {
			return err;
		}
	}
	/* Waiting for client to connect to stderr pipe */
	if ((err = do_ConnectNamedPipe(psi->hStdError, NULL)) != 0) {
		return err;
	}
	return 0;
}

int
enable_privilege(char *privname)
{
	LUID	luid;
	HANDLE	procToken = INVALID_HANDLE_VALUE;
	TOKEN_PRIVILEGES toke;
	int	stat = 0;

	if (!LookupPrivilegeValue(NULL, privname, &luid)) {
		goto enable_privilege_end;
	}

	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_QUERY|TOKEN_ADJUST_PRIVILEGES, &procToken)) {
		goto enable_privilege_end;
	}

	toke.PrivilegeCount = 1;
	toke.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	toke.Privileges[0].Luid = luid;

	if (!AdjustTokenPrivileges(procToken, FALSE, &toke, 0, NULL, 0)) {
		goto enable_privilege_end;
	}
	stat = 1;

enable_privilege_end:
	close_valid_handle(&(procToken));
	return (stat);
}

int
add_user_privilege(char *user, char *domain, char *priv_name)
{
	SID *user_sid = NULL;
	DWORD sid_sz = 0;
	HANDLE hToken = INVALID_HANDLE_VALUE;
	DWORD dwBufferSize = 0;
	PTOKEN_USER pTokenUser = NULL;

	LSA_UNICODE_STRING rights;
	LSA_HANDLE h_policy = INVALID_HANDLE_VALUE;
	LSA_OBJECT_ATTRIBUTES  obj_attrs;
	NTSTATUS lsa_stat;
	BOOL	rval = 1;
	WCHAR	*privnameW = NULL;
	int	priv_len = 0;

	if (priv_name == NULL)
		return 0;

	if (user == NULL || domain == NULL) {
		DWORD	sid_len_need;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
			return 0;
		}
		GetTokenInformation(hToken, TokenUser, NULL, 0, &dwBufferSize);
		if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
			pTokenUser = (PTOKEN_USER)malloc(dwBufferSize);
			if (pTokenUser == NULL) {
				CloseHandle(hToken);
				return 0;
			}
		} else {
			CloseHandle(hToken);
			return 0;
		}
		memset(pTokenUser, 0, dwBufferSize);
		if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwBufferSize, &dwBufferSize)) {
			CloseHandle(hToken);
			free(pTokenUser);
			return 0;
		}
		if (!IsValidSid(pTokenUser->User.Sid)) {
			CloseHandle(hToken);
			free(pTokenUser);
			return 0;
		}
		sid_len_need = GetLengthSid(pTokenUser->User.Sid);
		if ((user_sid = (SID *)LocalAlloc(LPTR, sid_len_need)) == NULL) {
			return 0;
		}

		if (CopySid(sid_len_need, user_sid, pTokenUser->User.Sid) == 0) {
			return 0;
		}
	} else {
		char fqdn[DNLEN+UNLEN+1] = {'\0'};
		char domain1[DNLEN+1] = "";
		DWORD domain_sz = 0;
		SID_NAME_USE sid_type;

		snprintf(fqdn, sizeof(fqdn)-1, "%s\\%s", domain, user);
		LookupAccountName(0, fqdn, user_sid, &sid_sz, domain1, &domain_sz, &sid_type);
		if (sid_sz <= 0)
			return 0;
		if ((user_sid = (SID *)LocalAlloc(LPTR, sid_sz)) == NULL) {
			return 0;
		}
		if (LookupAccountName(0, fqdn, user_sid, &sid_sz, domain1, &domain_sz, &sid_type) == 0)
			return 0;
	}
	priv_len = strlen(priv_name) + 1;
	privnameW = (WCHAR *)malloc(priv_len * sizeof(WCHAR));
	if (privnameW == NULL) {
		return 0;
	}
	mbstowcs(privnameW, priv_name, priv_len);
	rights.Buffer = privnameW;
	rights.Length = (USHORT)(wcslen(privnameW) * sizeof(WCHAR));
	rights.MaximumLength = (USHORT)((wcslen(privnameW)+1) * sizeof(WCHAR));
	ZeroMemory(&obj_attrs, sizeof(obj_attrs));
	rval = 0;
	if( LsaOpenPolicy(NULL, &obj_attrs, POLICY_ALL_ACCESS, &h_policy) != ERROR_SUCCESS ) {
		goto add_user_privilege_end;
	}
	if( (lsa_stat=LsaAddAccountRights( h_policy, user_sid, &rights, 1 )) != ERROR_SUCCESS ) {
		goto add_user_privilege_end;
	}
	rval = 0;

add_user_privilege_end:
	if (h_policy != INVALID_HANDLE_VALUE)
		LsaClose(h_policy);
	if (privnameW != NULL)
		(void)free(privnameW);
	if (user_sid != NULL)
		LocalFree(user_sid);
	return 1;
}

int
add_window_station_ace(HWINSTA hwin, SID *usid)
{
	int			ret = 1;
	SECURITY_INFORMATION	si;
	SECURITY_DESCRIPTOR	*sd = NULL;
	SECURITY_DESCRIPTOR	*sd_new = NULL;
	DWORD			sd_sz;
	DWORD			sd_sz_need;

	BOOL			hasDacl = 0;
	BOOL			defDacl = 0;
	ACL			*acl = NULL;
	ACL			*acl_new = NULL;
	ACL_SIZE_INFORMATION	acl_szinfo;
	DWORD			acl_new_sz;

	DWORD			i;
	VOID			*ace_temp;
	ACCESS_ALLOWED_ACE	*ace = NULL;

	si = DACL_SECURITY_INFORMATION;
	sd = NULL;
	sd_sz = 0;
	sd_sz_need = 0;
	if (GetUserObjectSecurity(hwin, &si, sd, sd_sz, &sd_sz_need) == 0) {

		if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
			if ((sd=(SECURITY_DESCRIPTOR *)malloc(sd_sz_need)) == NULL) {
				errno = GetLastError();
				goto fail;
			}
			memset((SECURITY_DESCRIPTOR *)sd, 0, sd_sz_need);
		}

		sd_sz = sd_sz_need;
		if (GetUserObjectSecurity(hwin, &si, sd, sd_sz,
			&sd_sz_need) == 0) {

			errno = GetLastError();
			goto fail;
		}
	}

	acl = NULL;
	if (GetSecurityDescriptorDacl(sd, &hasDacl, &acl, &defDacl) == 0) {
		errno = GetLastError();
		goto fail;
	}

	ZeroMemory(&acl_szinfo, sizeof(ACL_SIZE_INFORMATION));
	acl_szinfo.AclBytesInUse = sizeof(ACL);
	/* compute new acl size */
	acl_new_sz = acl_szinfo.AclBytesInUse +
		(2 * sizeof(ACCESS_ALLOWED_ACE)) +
	(2 * GetLengthSid(usid)) -
	(2 * sizeof(DWORD));

	if ((acl_new=(ACL *)malloc(acl_new_sz)) == NULL) {
		errno = GetLastError();
		goto fail;
	}
	memset((ACL *)acl_new, 0, acl_new_sz);


	if (InitializeAcl(acl_new, acl_new_sz, ACL_REVISION) == 0) {
		goto fail;
	}


	if (acl != NULL) {
		if (GetAclInformation(acl,
			(VOID *)&acl_szinfo, sizeof(ACL_SIZE_INFORMATION),
			AclSizeInformation) == 0) {
			errno = GetLastError();
			goto fail;
		}

		if (hasDacl) {
			ACL *acl_new_tmp;

			for (i=0; i < acl_szinfo.AceCount; i++) {

				if (GetAce(acl, i, (VOID **)&ace_temp) == 0) {
					errno  = GetLastError();
					goto fail;
				}
				acl_new_sz += ((ACE_HEADER *)ace_temp)->AceSize;
			}
			if( (acl_new_tmp=(ACL *)realloc(acl_new, acl_new_sz)) \
								     == NULL ) {
				errno = GetLastError();
				goto fail;
			}

			acl_new = acl_new_tmp;
			memset((ACL *)acl_new, 0, acl_new_sz);

			if( InitializeAcl(acl_new, acl_new_sz, ACL_REVISION) \
									== 0 ) {

				goto fail;
			}

			for (i=0; i < acl_szinfo.AceCount; i++) {
				if (GetAce(acl, i, (VOID **)&ace_temp) == 0) {
					errno  = GetLastError();
					goto fail;
				}

				/* add the ACE to the new  ACL */
				if (AddAce(acl_new, ACL_REVISION, MAXDWORD,
					ace_temp,
					((ACE_HEADER *)ace_temp)->AceSize) == 0) {
					errno = GetLastError();
					goto fail;
				}
			}
		}
	}


	/* add the first ACE to the windowstation */
	if( (ace=(ACCESS_ALLOWED_ACE *)\
			malloc(	sizeof(ACCESS_ALLOWED_ACE) +
		GetLengthSid(usid) -
		sizeof(DWORD))) == NULL) {
		errno = GetLastError();
		goto fail;
	}

	ace->Header.AceType  = ACCESS_ALLOWED_ACE_TYPE;
	ace->Header.AceFlags = CONTAINER_INHERIT_ACE |
		INHERIT_ONLY_ACE     |
	OBJECT_INHERIT_ACE;

	ace->Header.AceSize  = (WORD)(sizeof(ACCESS_ALLOWED_ACE) +
		GetLengthSid(usid) - sizeof(DWORD));
	ace->Mask            = 	GENERIC_READ |
		GENERIC_WRITE |
	GENERIC_EXECUTE |
	GENERIC_ALL;

	if (CopySid(GetLengthSid(usid), &ace->SidStart, usid) == 0) {
		errno = GetLastError();
		goto fail;
	}

	if (AddAce(acl_new, ACL_REVISION, MAXDWORD, (VOID *)ace,
		ace->Header.AceSize) == 0) {
		errno = GetLastError();
		goto fail;
	}


	/* add the second ACE to the windowstation */
	ace->Header.AceFlags = NO_PROPAGATE_INHERIT_ACE;
	ace->Mask            = 	WINSTA_ACCESSCLIPBOARD 	|
		WINSTA_ACCESSGLOBALATOMS|
	WINSTA_CREATEDESKTOP    |
	WINSTA_ENUMDESKTOPS	|
	WINSTA_ENUMERATE        |
	WINSTA_EXITWINDOWS      |
	WINSTA_READATTRIBUTES   |
	WINSTA_READSCREEN       |
	WINSTA_WRITEATTRIBUTES  |
	DELETE                  |
	READ_CONTROL            |
	WRITE_DAC               |
	WRITE_OWNER;
	if (AddAce(acl_new, ACL_REVISION, MAXDWORD, (VOID *)ace, ace->Header.AceSize) == 0) {
		errno = GetLastError();
		goto fail;
	}

	if ((sd_new=(SECURITY_DESCRIPTOR *)malloc(sd_sz)) == NULL) {
		errno = GetLastError();
		goto fail;
	}

	if (InitializeSecurityDescriptor(sd_new,
		SECURITY_DESCRIPTOR_REVISION) == 0) {
		errno = GetLastError();
		goto fail;
	}

	/* set new dacl for the security descriptor */
	if (SetSecurityDescriptorDacl(sd_new, TRUE, acl_new, FALSE) == 0) {
		errno = GetLastError();
		goto fail;
	}
	if (SetUserObjectSecurity(hwin, &si, sd_new) == 0) {
		goto fail;
	}


	ret = 0;
fail:

	if (ace) {
		(void)free(ace);
	}

	if (acl_new) {
		(void)free(acl_new);
	}

	if (sd) {
		(void)free(sd);
	}

	if (sd_new) {
		(void)free(sd_new);
	}

	return (ret);

}

int
add_desktop_ace(HDESK hdesk, SID *usid)
{
	int			ret = 1;
	SECURITY_INFORMATION	si = 0;
	SECURITY_DESCRIPTOR	*sd = NULL;
	SECURITY_DESCRIPTOR	*sd_new = NULL;
	DWORD			sd_sz = 0;
	DWORD			sd_sz_need = 0;

	BOOL			hasDacl = 0;
	BOOL			defDacl = 0;
	ACL			*acl = NULL;
	ACL			*acl_new = NULL;
	ACL_SIZE_INFORMATION	acl_szinfo = {0};
	DWORD			acl_new_sz = 0;

	DWORD			i = 0;
	VOID			*ace_temp = NULL;

	si = DACL_SECURITY_INFORMATION;
	sd = NULL;
	sd_sz = 0;
	sd_sz_need = 0;
	if (GetUserObjectSecurity(hdesk, &si, sd, sd_sz, &sd_sz_need) == 0) {

		if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {

			if ((sd=(SECURITY_DESCRIPTOR *)malloc(sd_sz_need)) == NULL) {
				errno = GetLastError();
				goto fail;
			}
			memset((SECURITY_DESCRIPTOR *)sd, 0, sd_sz_need);
		}

		sd_sz = sd_sz_need;
		if (GetUserObjectSecurity(hdesk, &si, sd, sd_sz,
			&sd_sz_need) == 0) {
			errno = GetLastError();
			goto fail;
		}
	}

	acl = NULL;
	if (GetSecurityDescriptorDacl(sd, &hasDacl, &acl, &defDacl) == 0) {
		errno = GetLastError();
		goto fail;
	}

	ZeroMemory(&acl_szinfo, sizeof(ACL_SIZE_INFORMATION));
	acl_szinfo.AclBytesInUse = sizeof(ACL);
	/* compute new acl size */

	acl_new_sz = acl_szinfo.AclBytesInUse +
		sizeof(ACCESS_ALLOWED_ACE) +
	GetLengthSid(usid) -
	sizeof(DWORD);

	if ((acl_new=(ACL *)malloc(acl_new_sz)) == NULL) {
		errno = GetLastError();
		goto fail;
	}
	memset((ACL *)acl_new, 0, acl_new_sz);

	if (InitializeAcl(acl_new, acl_new_sz, ACL_REVISION) == 0) {
		goto fail;
	}


	if (acl != NULL) {

		if (GetAclInformation(acl,
			(VOID *)&acl_szinfo, sizeof(ACL_SIZE_INFORMATION),
			AclSizeInformation) == 0) {
			errno = GetLastError();
			goto fail;
		}

		if (hasDacl) {
			ACL	*acl_new_tmp = NULL;

			for (i=0; i < acl_szinfo.AceCount; i++) {
				if (GetAce(acl, i, &ace_temp) == 0) {
					errno  = GetLastError();
					goto fail;
				}
				acl_new_sz += ((ACE_HEADER *)ace_temp)->AceSize;
			}

			if( (acl_new_tmp=(ACL *)realloc(acl_new,acl_new_sz)) \
								     == NULL ) {
				errno = GetLastError();
				goto fail;
			}
			acl_new = acl_new_tmp;

			memset((ACL *)acl_new, 0, acl_new_sz);

			if (InitializeAcl(acl_new, acl_new_sz, ACL_REVISION) == 0) {
				goto fail;
			}

			for (i=0; i < acl_szinfo.AceCount; i++) {
				if (GetAce(acl, i, &ace_temp) == 0) {
					errno  = GetLastError();
					goto fail;
				}

				/* add the ACE to the new  ACL */
				if (AddAce(acl_new, ACL_REVISION, MAXDWORD,
					ace_temp,
					((ACE_HEADER *)ace_temp)->AceSize) == 0) {
					errno = GetLastError();
					goto fail;
				}
			}
		}
	}

	/* add ace to the dacl */

	if (AddAccessAllowedAce(acl_new, ACL_REVISION, DESKTOP_ALL,
		usid) == 0) {
		errno = GetLastError();
		goto fail;
	}

	if ((sd_new=(SECURITY_DESCRIPTOR *)malloc(sd_sz)) == NULL) {
		errno = GetLastError();
		goto fail;
	}

	if (InitializeSecurityDescriptor(sd_new,
		SECURITY_DESCRIPTOR_REVISION) == 0) {
		errno = GetLastError();
		goto fail;
	}

	/* set new dacl for the security descriptor */

	if (SetSecurityDescriptorDacl(sd_new, TRUE, acl_new, FALSE) == 0) {
		errno = GetLastError();
		goto fail;
	}

	if (SetUserObjectSecurity(hdesk, &si, sd_new) == 0) {
		goto fail;
	}

	ret = 0;	/* success */
fail:

	if (acl_new)(void)free(acl_new);

	if (sd)(void)free(sd);

	if (sd_new)(void)free(sd_new);

	return (ret);

}

int
allow_window_station_desktop(char *user, char *domain)
{
	HWINSTA	hwin;
	HDESK hdesk;
	int	ret = 1;
	char fqdn[DNLEN+UNLEN+1] = {'\0'};
	char domain1[DNLEN+1] = "";
	DWORD domain_sz = 0;
	SID_NAME_USE sid_type;
	SID *usid = NULL;
	DWORD sid_sz = 0;

	if (user == NULL || domain == NULL) {
		DWORD	sid_len_need;
		HANDLE hToken = INVALID_HANDLE_VALUE;
		DWORD dwBufferSize = 0;
		PTOKEN_USER pTokenUser = NULL;

		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
			return 0;
		}
		GetTokenInformation(hToken, TokenUser, NULL, 0, &dwBufferSize);
		if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
			pTokenUser = (PTOKEN_USER)malloc(dwBufferSize);
			if (pTokenUser == NULL) {
				CloseHandle(hToken);
				return 0;
			}
		} else {
			CloseHandle(hToken);
			return 0;
		}
		memset(pTokenUser, 0, dwBufferSize);
		if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwBufferSize, &dwBufferSize)) {
			CloseHandle(hToken);
			free(pTokenUser);
			return 0;
		}
		if (!IsValidSid(pTokenUser->User.Sid)) {
			CloseHandle(hToken);
			free(pTokenUser);
			return 0;
		}
		sid_len_need = GetLengthSid(pTokenUser->User.Sid);
		if ((usid = (SID *)LocalAlloc(LPTR, sid_len_need)) == NULL) {
			return 0;
		}

		if (CopySid(sid_len_need, usid, pTokenUser->User.Sid) == 0) {
			return 0;
		}
	} else {
		snprintf(fqdn, sizeof(fqdn)-1, "%s\\%s", domain, user);
		LookupAccountName(0, fqdn, usid, &sid_sz, domain1, &domain_sz, &sid_type);
		if (sid_sz <= 0)
			return 0;
		if ((usid = (SID *)LocalAlloc(LPTR, sid_sz)) == NULL) {
			return 0;
		}
		if (LookupAccountName(0, fqdn, usid, &sid_sz, domain1, &domain_sz, &sid_type) == 0)
			return 0;
	}

	hwin = OpenWindowStation("winsta0", FALSE, READ_CONTROL | WRITE_DAC);
	if (hwin == NULL) {
		goto end;
	}

	if (!SetProcessWindowStation(hwin))
		goto end;

	hdesk = OpenDesktop("default", 0, FALSE, READ_CONTROL | WRITE_DAC | DESKTOP_WRITEOBJECTS | DESKTOP_READOBJECTS);
	if (hdesk == NULL) {
		goto end;
	}

	if (add_window_station_ace(hwin, usid)) {
		goto end;
	}

	if (add_desktop_ace(hdesk, usid)) {
		goto end;
	}

	ret = 0;

end:
	if (hwin)
		CloseWindowStation(hwin);
	if (hdesk)
		CloseDesktop(hdesk);
	if (usid != NULL)
		LocalFree(usid);
	return (ret);

}

void
free_environ(char ***env_array, int *used)
{
	int	i = 0;
	for (i=0; i<*used; i++) {
		free((*env_array)[i]);
		(*env_array)[i] = NULL;
	}
	free(*env_array);
	*env_array = NULL;
}

int
init_environ(HANDLE hToken, char ***env_array, int *used, int *total)
{
	wchar_t *env_block_copy = NULL;
	wchar_t *env_block = NULL;
	int j = 50;

	*used = 0;
	*env_array = (char **)malloc(sizeof(char *)*j);
	if (*env_array == NULL)
		return 1;
	*total = j;

	if (hToken == INVALID_HANDLE_VALUE) {
		return 0;
	}

	if(!CreateEnvironmentBlock(&env_block, hToken, FALSE)) {
		return 1;
	}
	env_block_copy = env_block;
	while (*env_block_copy) {
		char buf[4096] = {'\0'};
		wcstombs(buf, env_block_copy, wcslen(env_block_copy));
		(*env_array)[*used] = strdup(buf);
		if ((*env_array)[*used] == NULL) {
			DestroyEnvironmentBlock(env_block);
			free_environ(env_array, used);
			return 1;
		}
		(*used)++;
		if (*used == j) {
			j *= 2;
			*env_array = (char **)realloc(*env_array, j);
			if (*env_array) {
				DestroyEnvironmentBlock(env_block);
				free_environ(env_array, used);
				return 1;
			}
			*total = j;
		}
        env_block_copy += wcslen(env_block_copy) + 1;
    }
	DestroyEnvironmentBlock(env_block);
	return 0;
}

char*
get_environ(char ***env_array, int *used)
{
	int	i;
	size_t	len = 0;
	char *envp, *cp;

	if (*used == 0)
		return NULL;
	for (i=0; i<*used; i++)
		len += (strlen((*env_array)[i]) + 1);
	len++;
	envp = cp = (char *)malloc(len);
	if (cp == NULL) {
		return NULL;
	}
	for (i=0; i<*used; i++) {
		len = strlen((*env_array)[i]);
		memcpy(cp, (*env_array)[i], len);
		cp += len;
		*cp++ = '\0';
	}
	*cp = '\0';
	return envp;
}

int
find_environ_slot(char ***env_array, int *used, char *name)
{
	int	 i;
	int	 len = 1;
	if (name == NULL)
		return (-1);
	for (i=0; (*(name+i) != '=') && (*(name+i) != '\0'); ++i)
		++len;
	for (i=0; i<*used; ++i) {
		if (strncmp((*env_array)[i], name, len) == 0)
			return (i);
	}
	return (-1);
}

int
add_environ(char ***env_array, int *used, int *total, char *name, char *value)
{
	char *env;
	int	amt;
	int	i;

	if ((*name == '\0') || (*name == '\n'))
		return 1;
	if (*used == *total) {
		int	numenv_tmp = 0;
		char **env_array_tmp = NULL;

		numenv_tmp = *total * 2;
		env_array_tmp = (char **)realloc(*env_array, sizeof(char *)*numenv_tmp);
		if (env_array_tmp == NULL) {
			return 1;
		}
		*env_array = env_array_tmp;
		*total = numenv_tmp;
		for (i=*used; i < *total; i++) {
			(*env_array)[i] = NULL;
		}
	}

	amt = strlen(name) + 1;
	if (value)
		amt += strlen(value) + 1;
	env = (char *)malloc(amt);
	if (env == NULL) {
		return 1;
	}
	(void)strcpy(env, name);
	if (value) {
		(void)strcat(env, "=");
		(void)strcat(env, value);
	}
	if ((i = find_environ_slot(env_array, used, env)) < 0) {
		if ((*env_array)[*used])
			free((*env_array)[*used]);
		(*env_array)[*used] = env;
		(*used)++;
	} else  {
		if ((*env_array)[i])
			free((*env_array)[i]);
		(*env_array)[i] = env;
	}
	return 0;
}

void run_client_cmd(void *p)
{
	char pipename_append[PIPENAME_MAX_LENGTH] = {'\0'};
	char cmd_pipename[PIPENAME_MAX_LENGTH] = {'\0'};
	HANDLE hClientCmdPipe = INVALID_HANDLE_VALUE;
	DWORD exit_code = 1;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	HANDLE hJob = INVALID_HANDLE_VALUE;
	HANDLE hToken = INVALID_HANDLE_VALUE;
	int err = -1;
	char domain[DNLEN+1] = {'\0'};
	char username[UNLEN+1] = {'\0'};
	char password[LM20_PWLEN+1] = {'\0'};
	int cmd_len = 0;
	int i = 0;
	char cmdline[CMDLINE_LENGTH+1] = {'\0'};
	char cmdline_p[CMDLINE_LENGTH+1] = {'\0'};
	char cwd[MAX_PATH] = {'\0'};
	char *env_block = NULL;
	char **env_array = NULL;
	int env_used_size = 0;
	int env_total_size = 0;
	char **env_array_client = NULL;
	int env_used_size_client = 0;
	int env_total_size_client = 0;
	PROFILEINFO profileinfo;

	if (p == NULL)
		ExitThread(1);

	ZeroMemory(&si, sizeof(si));
	ZeroMemory(&profileinfo, sizeof(PROFILEINFO));
	strncpy(pipename_append, (char *)p, PIPENAME_MAX_LENGTH - 1);
	free(p);
	snprintf(cmd_pipename, PIPENAME_MAX_LENGTH - 1, "\\\\.\\pipe\\%s%s", INTERACT_CMD, pipename_append);
	err = create_pipe(PIPE_ACCESS_DUPLEX, cmd_pipename, &(hClientCmdPipe));
	if ((err != 0) || (hClientCmdPipe == INVALID_HANDLE_VALUE))
		goto run_client_cmd_end;
	if ((err = do_ConnectNamedPipe(hClientCmdPipe, NULL)) != 0)
		goto run_client_cmd_end;
	if (recv_string(hClientCmdPipe, domain) == -1) {
		goto run_client_cmd_end;
	}
	if (recv_string(hClientCmdPipe, username) == -1) {
		goto run_client_cmd_end;
	}
	if (recv_string(hClientCmdPipe, password) == -1) {
		goto run_client_cmd_end;
	}
	if (recv_string(hClientCmdPipe, (char *)&cmd_len) == -1) {
		goto run_client_cmd_end;
	}
	if (recv_string(hClientCmdPipe, cwd) == -1) {
		goto run_client_cmd_end;
	}
	i = 0;
	if (recv_string(hClientCmdPipe, (char *)&i) == -1) {
		goto run_client_cmd_end;
	}
	if (i > 0) {
		char buf[4096] = {'\0'};
		int j = 0;
		init_environ(INVALID_HANDLE_VALUE, &env_array_client, &env_used_size_client, &env_total_size_client);
		for (j=0; j<i; j++) {
			if (recv_string(hClientCmdPipe, buf) == -1) {
				goto run_client_cmd_end;
			}
			add_environ(&env_array_client, &env_used_size_client, &env_total_size_client, buf, NULL);
		}
	}
	strncpy(cmdline, "", sizeof(cmdline)-1);
	for (i = 0; i < cmd_len; i++) {
		if (recv_string(hClientCmdPipe, cmdline_p) == -1) {
			goto run_client_cmd_end;
		}
		strncat(cmdline, " ", sizeof(cmdline)-1);
		strncat(cmdline, cmdline_p, sizeof(cmdline)-1);
	}
	send_string(hClientCmdPipe, "");
	add_user_privilege(username, domain, SE_SERVICE_LOGON_NAME);
	add_user_privilege(username, domain, SE_BATCH_LOGON_NAME);
	add_user_privilege(username, domain, SE_INTERACTIVE_LOGON_NAME);
	allow_window_station_desktop(username, domain);
	if (LogonUser(username, domain, password, LOGON32_LOGON_BATCH, LOGON32_PROVIDER_DEFAULT, &hToken) == 0) {
		if (LogonUser(username, domain, password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hToken) == 0) {
			goto run_client_cmd_end;
		}
	}
	memset(password, 0, sizeof(password));
	si.cb = sizeof(si);
	si.wShowWindow = SW_HIDE;
	si.lpDesktop = "winsta0\\default";
	si.dwFlags = STARTF_USESHOWWINDOW;
	if (create_std_pipes(&si, pipename_append, 1) != 0) {
		goto run_client_cmd_end;
	}
	if (connectstdpipes(&si, 1) != 0) {
		goto run_client_cmd_end;
	}
	profileinfo.dwSize = sizeof(PROFILEINFO);
	profileinfo.lpUserName = username;
	if (!LoadUserProfile(hToken, &profileinfo)) {
		goto run_client_cmd_end;
	}
	if (cwd[0] == '\0') {
		i = sizeof(cwd);
		if (!GetUserProfileDirectory(hToken, &cwd[0], (DWORD *)&i)) {
			goto run_client_cmd_end;
		}
	}
	init_environ(hToken, &env_array, &env_used_size, &env_total_size);
	for (i=0; i<env_used_size_client; i++) {
		add_environ(&env_array, &env_used_size, &env_total_size, env_array_client[i], NULL);
	}
	env_block = get_environ(&env_array, &env_used_size);
	hJob = CreateJobObject(NULL, NULL);
	if (CreateProcessAsUser(hToken, NULL, &cmdline[1], NULL, NULL, TRUE,
							CREATE_DEFAULT_ERROR_MODE|CREATE_SUSPENDED|CREATE_NEW_CONSOLE|CREATE_NEW_PROCESS_GROUP,
							env_block, &cwd[0], &si, &pi)) {
		AssignProcessToJobObject(hJob, pi.hProcess);
		ResumeThread(pi.hThread);
		WaitForSingleObject(pi.hProcess, INFINITE);
		GetExitCodeProcess(pi.hProcess, &exit_code);
		TerminateJobObject(hJob, exit_code);
		close_valid_handle(&(pi.hProcess));
		close_valid_handle(&(pi.hThread));
	} else {
		exit_code = GetLastError();
	}
run_client_cmd_end:
	if (si.hStdOutput != INVALID_HANDLE_VALUE)
		FlushFileBuffers(si.hStdOutput);
	if (si.hStdError != INVALID_HANDLE_VALUE)
		FlushFileBuffers(si.hStdError);
	if (profileinfo.hProfile != INVALID_HANDLE_VALUE)
		UnloadUserProfile(hToken, profileinfo.hProfile);
	if (env_array != NULL)
		free_environ(&env_array, &env_used_size);
	if (env_array_client != NULL)
		free_environ(&env_array_client, &env_used_size_client);
	if (env_block != NULL)
		free(env_block);
	close_valid_handle(&(hJob));
	close_valid_handle(&(hToken));
	disconnect_close_pipe(&(si.hStdInput));
	disconnect_close_pipe(&(si.hStdOutput));
	disconnect_close_pipe(&(si.hStdError));
	send_string(hClientCmdPipe, (char *)&exit_code);
	disconnect_close_pipe(&(hClientCmdPipe));
	ExitThread(exit_code);
}

DWORD WINAPI main_thread(void *unused)
{
	_fcloseall();
	ZeroMemory(&ss, sizeof(ss));
	ss.dwCheckPoint		= 0;
	ss.dwServiceType	= SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS;
	ss.dwCurrentState	= g_dwCurrentState;
	ss.dwControlsAccepted	= SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
	ss.dwWaitHint = 3000;
	if (g_ssHandle != 0) SetServiceStatus(g_ssHandle, &ss);

	g_dwCurrentState = SERVICE_RUNNING;
	ss.dwCurrentState = g_dwCurrentState;
	if (g_ssHandle != 0) SetServiceStatus(g_ssHandle, &ss);

    enable_privilege(SE_CREATE_TOKEN_NAME);
	enable_privilege(SE_ASSIGNPRIMARYTOKEN_NAME);
	enable_privilege(SE_INCREASE_QUOTA_NAME);
	enable_privilege(SE_SERVICE_LOGON_NAME);
	enable_privilege(SE_BATCH_LOGON_NAME);
	enable_privilege(SE_INTERACTIVE_LOGON_NAME);
	enable_privilege(SE_TCB_NAME);
	enable_privilege(SE_BACKUP_NAME);
	enable_privilege(SE_RESTORE_NAME);
	add_user_privilege(NULL, NULL, SE_CREATE_TOKEN_NAME);
	add_user_privilege(NULL, NULL, SE_INCREASE_QUOTA_NAME);
	add_user_privilege(NULL, NULL, SE_ASSIGNPRIMARYTOKEN_NAME);
	add_user_privilege(NULL, NULL, SE_SERVICE_LOGON_NAME);
	add_user_privilege(NULL, NULL, SE_BATCH_LOGON_NAME);
	add_user_privilege(NULL, NULL, SE_INTERACTIVE_LOGON_NAME);
	add_user_privilege(NULL, NULL, SE_TCB_NAME);

	allow_window_station_desktop(NULL, NULL);

    while(!quit) {
		char client_pipename[READBUF_SIZE] = {'\0'};
		HANDLE client_thread = INVALID_HANDLE_VALUE;
		char cmd_pipename[PIPENAME_MAX_LENGTH] = {'\0'};
        HANDLE hSvrCmdPipe = INVALID_HANDLE_VALUE;
        int err = -1;

		if (hSvrCmdPipe != INVALID_HANDLE_VALUE)
			disconnect_close_pipe(&(hSvrCmdPipe));
		snprintf(cmd_pipename, PIPENAME_MAX_LENGTH - 1, "\\\\.\\pipe\\%ssvr", INTERACT_CMD);
		err = create_pipe(PIPE_ACCESS_OUTBOUND, cmd_pipename, &(hSvrCmdPipe));
		if ((err != 0) || (hSvrCmdPipe == INVALID_HANDLE_VALUE))
			continue;
		if ((err = do_ConnectNamedPipe(hSvrCmdPipe, NULL)) != 0)
			continue;
		itoa(GetTickCount(), client_pipename, 10);
		if (send_string(hSvrCmdPipe, client_pipename) == -1)
			continue;
		client_thread = (HANDLE)_beginthread(run_client_cmd, 0, (void *)strdup(client_pipename));
		close_valid_handle(&(client_thread));
		disconnect_close_pipe(&(hSvrCmdPipe));
		hSvrCmdPipe = INVALID_HANDLE_VALUE;
	}

	return 0;
}

void
WINAPI
PTLServerHandler(DWORD dwControl)
{
	SERVICE_STATUS ss;

	ZeroMemory(&ss, sizeof(ss));
	ss.dwServiceType        = SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS;
	ss.dwCurrentState       = g_dwCurrentState;
	ss.dwControlsAccepted   = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;

	switch (dwControl) {
		case SERVICE_CONTROL_STOP:
		case SERVICE_CONTROL_SHUTDOWN:
			// DONE: When you receive a stop request, update the global state
			//      variable to indicate that a STOP is pending. You need
			//      to then ACK the SCM by calling SetServiceStatus. Set
			//      the check point to 1 and the wait hint to 1 second,
			//      since we are going to wait for the server to shutdown.

			g_dwCurrentState    = SERVICE_STOP_PENDING;
			ss.dwCurrentState   = g_dwCurrentState;
			ss.dwCheckPoint     = 1;
			ss.dwWaitHint       = 1000;
			if (g_ssHandle != 0) SetServiceStatus(g_ssHandle, &ss);

			TerminateThread(g_hthreadMain, 0);
			ReleaseMutex(hStop);
			CloseHandle(g_hthreadMain);
			break;

		default:
			if (g_ssHandle != 0) SetServiceStatus(g_ssHandle, &ss);
			break;
	}
}

void
WINAPI
PTLServerMain(DWORD dwArgc, LPTSTR *rgszArgv)
{
	DWORD	dwTID;
	DWORD	dwWait;
	SERVICE_STATUS	ss;

	g_ssHandle = RegisterServiceCtrlHandler(g_PTLServerName, PTLServerHandler);
	if (g_ssHandle == 0) {
		ErrorMessage("RegisterServiceCtrlHandler");
	}
	g_hthreadMain = (HANDLE) _beginthreadex(0, 0, main_thread, NULL, 0, &dwTID);
	if (g_hthreadMain == 0) {
		ErrorMessage("CreateThread");
	}

	dwWait = WaitForSingleObject(g_hthreadMain, INFINITE);
	if (dwWait != WAIT_OBJECT_0) {
		ErrorMessage("WaitForSingleObject");
	}
	ZeroMemory(&ss, sizeof(ss));
	ss.dwServiceType        = SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS;
	ss.dwCurrentState       = SERVICE_STOPPED;
	ss.dwControlsAccepted   = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;

	if (g_ssHandle != 0) SetServiceStatus(g_ssHandle, &ss);
	exit(0);
}

int
main(int argc, char *argv[])
{
	int reg = 0;
	int unreg = 0;
	int stalone = 0;
	SC_HANDLE schManager;
	SC_HANDLE schSelf;
	TCHAR	szFileName[MAX_PATH];

	if (argc > 1) {
		if (strcmp(argv[1], "-R") == 0)
			reg = 1;
		else if (strcmp(argv[1], "-U") == 0)
			unreg = 1;
		else if (strcmp(argv[1], "-N") == 0)
			stalone = 1;
		else {
			fprintf(stderr, "Unknown argument: %s\n", argv[1]);
			exit(-1);
		}
	}

	if (reg || unreg) {
		schManager = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS);
		if (schManager == 0) {
			ErrorMessage("OpenSCManager");
		}
		if (reg) {
			GetModuleFileName(0, szFileName, sizeof(szFileName)/sizeof(*szFileName));
			printf("Installing service %s\n", g_PTLServerName);
			schSelf = CreateService(schManager, g_PTLServerName, __TEXT("PTL_RS"), SERVICE_ALL_ACCESS,
									SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS,
									SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
									szFileName, 0, 0, 0, 0, 0);
			if (schSelf) {
				printf("Service %s installed successfully!\n", g_PTLServerName);
				if (StartService(schSelf, 0, NULL)) {
					printf("Service %s started successfully!\n", g_PTLServerName);
				} else {
					ErrorMessage("StartService");
				}
			} else {
				ErrorMessage("CreateService");
			}
		} else if (unreg) {
			SERVICE_STATUS sp;
			schSelf = OpenService(schManager, g_PTLServerName, DELETE|SERVICE_STOP|SERVICE_QUERY_STATUS);
			if (schSelf) {
				int i = 0;
				try_stop:
				if (QueryServiceStatus(schSelf, &sp)) {
					if (sp.dwCurrentState != SERVICE_STOPPED) {
						i++;
						ControlService(schSelf, SERVICE_CONTROL_STOP, &sp);
						Sleep(1000);
						goto try_stop;
					} else if (i > 0) {
						printf("Service %s stopped successfully!\n", g_PTLServerName);
					}
				} else {
					ErrorMessage("QueryServiceStatus");
				}
				if (DeleteService(schSelf)) {
					printf("Service %s uninstalled successfully!\n", g_PTLServerName);
				} else {
					ErrorMessage("DeleteService");
				}
			} else {
				ErrorMessage("OpenService failed");
			}
		}
		if (schSelf != 0)
				CloseServiceHandle(schSelf);
		if (schManager != 0)
			CloseServiceHandle(schManager);
	} else if (stalone) {
		main_thread(NULL);
	} else {		/* run as service */
		SERVICE_TABLE_ENTRY ServiceTable[] = {
			{(TCHAR *)g_PTLServerName, PTLServerMain},
			{ 0 }
		};
		hStop = CreateMutex(NULL, TRUE, NULL);
		if (!StartServiceCtrlDispatcher(ServiceTable)) {
			ErrorMessage("StartServiceCntrlDispatcher");
		}
		CloseHandle(hStop);
	}
	return (0);
}
