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
		&bytes, // number of bytes written
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
			&bytes, // number of bytes read
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

/**
* @brief
*	Connect or disconnect resource at remote host.
*
* @param[in]	remote_host - name of the remote host
* @param[in]	remote_resourcename - name of the remote resource
* @param[in]	bEstablish - connect or disconnect. connect if true, disconnect otherwise
*
* @return      BOOL
* @retval	TRUE - success
* @retval	FALSE - failure
*
*/
BOOL
connect_remote_resource(const char *remote_host, const char *remote_resourcename, BOOL bEstablish)
{
	char remote_resource_path[PIPENAME_MAX_LENGTH] = {0};
	DWORD rc = 0;
	/* Prepare remote resource name e.g. \\<remote_host>\<remote_resourcename> */
	sprintf(remote_resource_path, "\\\\%s\\%s", remote_host, remote_resourcename);
	/* Disconnect or connect to the resource, based on bEstablish */
	if (bEstablish) {
		NETRESOURCE nr;
		nr.dwType = RESOURCETYPE_ANY;
		nr.lpLocalName = NULL;
		nr.lpRemoteName = (LPTSTR)&remote_resource_path;
		nr.lpProvider = NULL;
		/* Establish connection to remote resource without username/pwd */
		rc = WNetAddConnection2(&nr, NULL, NULL, FALSE);
		if (rc == NO_ERROR || rc == ERROR_ALREADY_ASSIGNED)
			return TRUE;
	}
	else {
		rc = WNetCancelConnection2(remote_resource_path, 0, TRUE);/* Disconnect resource */
		if(rc == NO_ERROR || rc == ERROR_NOT_CONNECTED)
			return TRUE;
	}

	SetLastError(rc);
	return FALSE;
}

/**
* @brief
*	This function tries to wait for named pipe to be available at named pipe server, making sure that
*  the named pipe exists and is available.
*  Connect to the named pipe, avoiding connection race that can occur if named pipe
*  client connects between CreateNamedPipe() and ConnectNamedPipe()
*  calls i.e. WaitNamedPipe() at client gets called before ConnectNamedPipe() call at server. WaitNamedPipe()
*  in such case returns succesfully but subsequent CreateFile() call fails with ERROR_PIPE_NOT_CONNECTED.
*  Retry CreateFile() multiple times untill the named pipe gets connected at named pipe server or untill the max retry.
*
*  Also, if the Pipe is not yet created at server, the call to WaitNamedPipe() at client fails with error
*  ERROR_FILE_NOT_FOUND. We need to retry WaitNamedPipe() multiple times at the client to make sure that the
*  named pipe is created at named server.
*
* @param[in]	pipename - Name of the named pipe.
* @param[in]   timeout - timeout for wait
* @param[in]   readwrite_accessflags - read/write access flags for the named pipe
*
* @return  HANDLE
* @retval	a valid handle to the pipe - success
* @retval	INVALID_HANDLE_VALUE - Failed to obtain a valid handle to the named pipe.
*
*/
HANDLE
do_WaitNamedPipe(char *pipename, DWORD timeout, DWORD readwrite_accessflags)
{
	HANDLE hPipe = INVALID_HANDLE_VALUE;
	int err = 0;
	int i = 0;
	int j = 0;
	int retry = 10;
	int retry2 = 10;

	SECURITY_ATTRIBUTES SecAttrib = {0};
	SECURITY_DESCRIPTOR SecDesc;

	if (pipename == NULL)
		return INVALID_HANDLE_VALUE;

	if (InitializeSecurityDescriptor(&SecDesc, SECURITY_DESCRIPTOR_REVISION) == 0)
		return INVALID_HANDLE_VALUE;

	if (SetSecurityDescriptorDacl(&SecDesc, TRUE, NULL, TRUE) == 0)
		return INVALID_HANDLE_VALUE;

	SecAttrib.nLength = sizeof(SECURITY_ATTRIBUTES);
	SecAttrib.lpSecurityDescriptor = &SecDesc;;
	SecAttrib.bInheritHandle = TRUE;

	while (i++ < retry) {
		/* Connect to the remote process pipe */
		if (WaitNamedPipe(pipename, timeout)) {
			while (j++ < retry2) {
				hPipe = CreateFile(pipename, readwrite_accessflags, 0, &SecAttrib, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_NO_BUFFERING, NULL);
				if (GetLastError() == ERROR_PIPE_NOT_CONNECTED) {
					Sleep(1000);
				} else {
					break;
				}
			}
			break;
		} else if (GetLastError() == ERROR_FILE_NOT_FOUND) {
			//retry = 100;
			Sleep(1000);
		}
	}
	return hPipe;
}

/**
* @brief
*	Generic function for handling the remote stdout/stderr via pipe.
*
* @param[in]	hPipe_remote_std - a HANDLE to pipe handling stdout/stderr.
* @param[in]	is_stdout - is hPipe_remote_std is for stdout
*
* @return      int
* @retval      -1, no data or broken pipe
* @retval      0, successfully read
*
*/
int
handle_stdoe_pipe(HANDLE hPipe_remote_std, int is_stdout)
{
	char readbuf[READBUF_SIZE] = {0};
	DWORD dwRead = 0;
	DWORD dwAvail = 0;
	DWORD dwErr = 0;
	DWORD dw_rc = 0;

	if (hPipe_remote_std == INVALID_HANDLE_VALUE)
		return -1;

	strncpy(readbuf, "", READBUF_SIZE - 1);
	dwRead = 0;
	/*
	 * Peek into the named pipe and see if there is any data to read, if yes, read it.
	 * ReadFile() should never block as we call it only when we know for certain that
	 * there is data to be read from pipe.
	 */
	dw_rc = PeekNamedPipe(hPipe_remote_std, NULL, 0, NULL, &dwAvail, NULL);
	if (dw_rc == 0) { /* PeekNamedPipe() fails */
		dwErr = GetLastError();
		if (dwErr == ERROR_NO_DATA || dwErr == ERROR_BROKEN_PIPE || dwErr == ERROR_PIPE_NOT_CONNECTED) {
			return -1;
		}
	}
	while (dwAvail > 0) {
		if (!ReadFile(hPipe_remote_std, readbuf, READBUF_SIZE, &dwRead, NULL) || dwRead == 0) {
			dwErr = GetLastError();
			if (dwErr == ERROR_NO_DATA) {
				return -1;
			}
		}
		if (dwRead != 0) {
			readbuf[ dwRead / sizeof(char) ] = '\0';
			if (is_stdout) {
			    fprintf(stdout, "%s", readbuf);
	            fflush(stdout);
			} else {
                fprintf(stderr, "%s", readbuf);
                fflush(stderr);
			}
		}
		/* When ReadFile returns with broken pipe, valid data may still be returned so break only after handling any data */
		if (dwErr == ERROR_BROKEN_PIPE || dwErr == ERROR_PIPE_NOT_CONNECTED) {
			return -1;
		}

		dw_rc = PeekNamedPipe(hPipe_remote_std, NULL, 0, NULL, &dwAvail, NULL);
		if (dw_rc == 0) { /* PeekNamedPipe() fails */
			dwErr = GetLastError();
			if (dwErr == ERROR_NO_DATA || dwErr == ERROR_BROKEN_PIPE || dwErr == ERROR_PIPE_NOT_CONNECTED) {
				return -1;
			}
		}
	}
	return 0;
}

/**
* @brief
*	Thread function for listening to console If the user types in something, this function
*  will pass it to the remote host's command shell. ReadConsole() returns after pressing the ENTER key.
*
* @param[in]	p - Thread argument. Expected to contain pointer to a HANDLE to remote stdin pipe.
*
* @return  void
*
*/
void
listen_remote_stdinpipe_thread(void *p)
{
	HANDLE hconsole_input = INVALID_HANDLE_VALUE;
	char inputbuf[CONSOLE_BUFSIZE] = {0};
	DWORD nBytesRead = 0;
	DWORD nBytesWrote = 0;
	HANDLE hpipe_remote_stdin = INVALID_HANDLE_VALUE;

	hconsole_input = GetStdHandle(STD_INPUT_HANDLE);
	if (hconsole_input == INVALID_HANDLE_VALUE || p == NULL)
		return;
	hpipe_remote_stdin = *((HANDLE*)p);

	for (;;) {
		ZeroMemory(&inputbuf[0], sizeof(inputbuf));
		/* Read the user input on console */
		if (!ReadConsole(hconsole_input, inputbuf, CONSOLE_BUFSIZE, &nBytesRead, NULL)) {
			DWORD dwErr = GetLastError();
			if (dwErr == ERROR_NO_DATA)
				break;
		}
		/* Write the console input to remote stdin pipe */
		if (!WriteFile(hpipe_remote_stdin, inputbuf, nBytesRead, &nBytesWrote, NULL) || nBytesRead != nBytesWrote)
			break;
		Sleep(1);
	}
	ExitThread(0);
}

/**
* @brief
*	Start threads to listen on pipes that connect to remote command's standard out/err/in.
*
* @param[in]	phout - Pointer to handle to the pipe connected to remote command's standard output.
* @param[in]	pherror - Pointer to handle to the pipe connected to remote command's standard error.
* @param[in]	phin - Pointer to handle to the pipe connected to remote command's standard input.
*
* @return  void
*
*/
void
listen_remote_stdpipes(HANDLE *phout, HANDLE *pherror, HANDLE *phin)
{
	/* Start a thread to listen to write remote command's standard input */
	if (phin) {
		HANDLE hconsole_input_thread = INVALID_HANDLE_VALUE;
		hconsole_input_thread = (HANDLE)_beginthread(listen_remote_stdinpipe_thread, 0, phin);
		close_valid_handle(&(hconsole_input_thread));
	}

	for (;;) {
		int rc = 0;
		rc = handle_stdoe_pipe(*pherror, FALSE);
		rc += handle_stdoe_pipe(*phout, TRUE);
		if (rc != 0)
			break;
		Sleep(1);
	}
}

/**
* @brief
*	Wait for the named pipes that redirect remote process's stdin/stdout/stderr.
*
* @param[in]	remote_host - name of the remote host
* @param[in]	pipename_append - appendix to standard pipe name
* @param[in]	connect_stdin - whether to connect stdin or not. Connect if true.
*
* @return  BOOL
* @retval	TRUE - success
* @retval	FALSE - failure
*
*/
BOOL
execute_remote_shell_command(char *remote_host, char *pipename_append, BOOL connect_stdin)
{
	char stdout_pipe[PIPENAME_MAX_LENGTH] = {0};
	char stdin_pipe[PIPENAME_MAX_LENGTH] = {0};
	char stderr_pipe[PIPENAME_MAX_LENGTH] = {0};
	int retry = 0;
	int max_retry = 10;
	int retry_interval = 1000; /* interval between each retry */
	HANDLE hPipe_remote_stdout = INVALID_HANDLE_VALUE;
	HANDLE hPipe_remote_stdin = INVALID_HANDLE_VALUE;
	HANDLE hPipe_remote_stderr = INVALID_HANDLE_VALUE;

	/* Pipe that redirects stdout of remote process */
	snprintf(stdout_pipe, PIPENAME_MAX_LENGTH - 1, "\\\\%s\\pipe\\%s%s", remote_host, INTERACT_STDOUT, pipename_append);
	/* Pipe that redirects stderr of remote process */
	snprintf(stderr_pipe, PIPENAME_MAX_LENGTH - 1, "\\\\%s\\pipe\\%s%s", remote_host, INTERACT_STDERR, pipename_append);
	/* Pipe that redirects user input to the remote process */
	snprintf(stdin_pipe, PIPENAME_MAX_LENGTH - 1, "\\\\%s\\pipe\\%s%s", remote_host, INTERACT_STDIN, pipename_append);
	while (retry++ < max_retry) {
		/* Wait for the stdout pipe to be available. Open an handle to it once it is available. */
		if (hPipe_remote_stdout == INVALID_HANDLE_VALUE)
			hPipe_remote_stdout = do_WaitNamedPipe(stdout_pipe, (int)(PIPE_MAX_WAITTIME/max_retry), GENERIC_READ);
		/* Wait for the stderr pipe to be available. Open an handle to it once it is available. */
		if (hPipe_remote_stderr == INVALID_HANDLE_VALUE)
			hPipe_remote_stderr = do_WaitNamedPipe(stderr_pipe, (int)(PIPE_MAX_WAITTIME/max_retry), GENERIC_READ);
		if (connect_stdin) {
			/* Wait for the stdin pipe to be available. Open an handle to it once it is available. */
			if (hPipe_remote_stdin == INVALID_HANDLE_VALUE)
				hPipe_remote_stdin = do_WaitNamedPipe(stdin_pipe, (int)(PIPE_MAX_WAITTIME/max_retry), GENERIC_WRITE);
		}
		if (connect_stdin) {
			if (hPipe_remote_stdin != INVALID_HANDLE_VALUE
				&& hPipe_remote_stdout != INVALID_HANDLE_VALUE
				&& hPipe_remote_stderr != INVALID_HANDLE_VALUE)
				break;
		}
		else if (hPipe_remote_stdout != INVALID_HANDLE_VALUE && hPipe_remote_stderr != INVALID_HANDLE_VALUE)
			break;
		/* One of the pipes failed, try it again after <retry_interval> milliseconds */
		Sleep(retry_interval);
	}

	if (hPipe_remote_stdout == INVALID_HANDLE_VALUE || hPipe_remote_stderr == INVALID_HANDLE_VALUE)
		return FALSE;
	if (connect_stdin && hPipe_remote_stdin == INVALID_HANDLE_VALUE)
		return FALSE;
	/*
	* Listen to these pipes.
	* Read the redirected stdout and write to the stdout.
	* Read the redirected stderr and write to the stderr.
	* Read the user input and redirect it to the stdin pipe.
	*/
	if (connect_stdin)
		listen_remote_stdpipes(&hPipe_remote_stdout, &hPipe_remote_stderr, &hPipe_remote_stdin);
	else
		listen_remote_stdpipes(&hPipe_remote_stdout, &hPipe_remote_stderr, NULL);
	close_valid_handle(&(hPipe_remote_stdout));
	close_valid_handle(&(hPipe_remote_stderr));
	close_valid_handle(&(hPipe_remote_stdin));
	return TRUE;
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
init_environ(char ***env_array, int *used, int *total)
{
	int j = 50;

	*used = 0;
	*env_array = (char **)malloc(sizeof(char *)*j);
	if (*env_array == NULL)
		return 1;
	*total = j;
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

int
main(int argc, char *argv[])
{
    char myid[PIPENAME_MAX_LENGTH] = {'\0'};
	char cmd_pipename[PIPENAME_MAX_LENGTH] = {0};
	char err_msg[BUFSIZ] = {'\0'};
	char *perr_msg = NULL;
	HANDLE hCmdPipe = INVALID_HANDLE_VALUE;
	char remote_hostname[MAX_COMPUTERNAME_LENGTH+1] = {'\0'};
	DWORD rh_len = sizeof(remote_hostname);
	int len = DNLEN+UNLEN+1;
	char dn[DNLEN+UNLEN+1] = {'\0'};
	char username[UNLEN+1] = {'\0'};
	char domain[DNLEN+1] = {'\0'};
	CREDENTIAL *cred = NULL;
	char *password = NULL;
	int password_len = 0;
	char *p = NULL;
	int i = 1;
	char cwd[MAX_PATH+1] = {'\0'};
	char **env_array = NULL;
	int env_used_size = 0;
	int env_total_size = 0;
	int exit_code = 1;

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

	GetComputerName(remote_hostname, &rh_len);
	while (i < argc) {
		if (!strncmp(argv[i], "-u", 2) || !strncmp(argv[i], "--user", 6)) {
			strncpy(username, argv[i+1], sizeof(username)-1);
			i += 2;
		} else if (!strncmp(argv[i], "-p", 2) || !strncmp(argv[i], "--password", 6)) {
			password = strdup(argv[i+1]);
			i += 2; 
	    } else if (!strncmp(argv[i], "-h", 2) || !strncmp(argv[i], "--host", 6)) {
			strncpy(remote_hostname, argv[i+1], sizeof(remote_hostname)-1);
			i += 2; 
		} else if (!strncmp(argv[i], "-c", 2) || !strncmp(argv[i], "--cwd", 6)) {
			strncpy(cwd, argv[i+1], sizeof(cwd)-1);
			i += 2; 
		} else if (!strncmp(argv[i], "-e", 2) || !strncmp(argv[i], "--env", 6)) {
			if (env_array == NULL) {
				init_environ(&env_array, &env_used_size, &env_total_size);
			}
			add_environ(&env_array, &env_used_size, &env_total_size, argv[i+1], NULL);
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

	if (password == NULL) {
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
	}

	if (cwd[0] == '\0') {
		GetCurrentDirectory(sizeof(cwd)-1, &cwd[0]);
	}

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
	if (send_string(hCmdPipe, cwd) == -1) {
		perr_msg = "failed to send cwd to remote server\n";
		goto end;
	}
	if (send_string(hCmdPipe, (char *)&env_used_size) == -1) {
		perr_msg = "failed to send env len to remote server\n";
		goto end;
	}
	if (env_used_size > 0) {
		int i = 0;
		for (i=0; i <env_used_size; i++) {
			if (send_string(hCmdPipe, env_array[i]) == -1) {
				perr_msg = "failed to send env to remote server\n";
				goto end;
			}
		}
	}
	while (i < argc) {
		if (send_string(hCmdPipe, argv[i]) == -1) {
			perr_msg = "failed to send cmdline to remote server\n";
			goto end;
		}
		i++;
	}
	memset(err_msg, 0, sizeof(err_msg));
	strncpy(err_msg, "Failed to retrive ack from server\n", sizeof(err_msg)-1);
	if(recv_string(hCmdPipe, err_msg) == -1) {
		perr_msg = "failed to retrive ack from server\n";
		goto end;
	}
	if (strlen(err_msg) != 0) {
		perr_msg = err_msg;
		goto end;
	}
	if(execute_remote_shell_command(remote_hostname, myid, 1) == FALSE) {
		fprintf(stderr, "Couldn't execute remote shell at host %s\n", remote_hostname);
		return -1;
	}
	if (recv_string(hCmdPipe, (char *)&exit_code) == -1) {
		perr_msg = "failed tp retrive exit code from server\n";
		goto end;
	}
end:
	CredFree(&cred);
	if (cred != NULL) {
		memset(cred, 0, sizeof(CREDENTIAL));
	}
	memset(password, 0, password_len);
	if (env_array != NULL) {
		free_environ(&env_array, &env_used_size);
	}
	disconnect_close_pipe(&(hCmdPipe));
	connect_remote_resource(remote_hostname, "IPC$", FALSE);
	if (perr_msg != NULL) {
		fprintf(stderr, "%s", perr_msg);
	}
	exit(exit_code);
}
