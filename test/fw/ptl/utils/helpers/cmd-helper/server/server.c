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

void WINAPI PTLServerMain(DWORD dwArgc, LPTSTR *rgszArgv);
void WINAPI PTLServerHandler(DWORD dwControl);
DWORD WINAPI main_thread(void *pv);

const TCHAR * const     g_PTLServerName = __TEXT("PTL_RS");
HANDLE                  g_hthreadMain = 0;
SERVICE_STATUS_HANDLE   g_ssHandle = 0;
DWORD                   g_dwCurrentState = SERVICE_START_PENDING;
HANDLE	hStop = NULL;
SERVICE_STATUS			ss;

int run_client_cmd(char *id)
{
	char                    pipename_append[PIPENAME_MAX_LENGTH] = {'\0'};
	char                    cmdline[PBS_CMDLINE_LENGTH] = {'\0'};
	DWORD                   exit_code = 0;
	STARTUPINFO             si;

	if (id == NULL)
		return -1;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	si.wShowWindow = SW_HIDE;

	/*
	* Create std pipes and wait for client to connect to these pipes
	*/
	strncpy(pipename_append, id, PIPENAME_MAX_LENGTH - 1);
	if (create_std_pipes(&si, pipename_append, 1) != 0)
		return -1;
	if (connectstdpipes(&si, 1) != 0) {
		/*
		* Close the standard out/in/err handles before returning
		*/
		close_valid_handle(&(si.hStdOutput));
		close_valid_handle(&(si.hStdError));
		close_valid_handle(&(si.hStdInput));
		return -1;
	}

	/*
	* Initialize the interactive command shell
	* cmd.exe /q turns echo off
	*/
	strncpy(cmdline, "cmd.exe /q", _countof(cmdline) - 1);
	/*
	* Run an interactive command shell, flush the file buffers
	*/
	if (run_command_si_blocking(&si, cmdline, &exit_code) == 0) {
		if (si.hStdOutput != INVALID_HANDLE_VALUE)
			FlushFileBuffers(si.hStdOutput);
		if (si.hStdError != INVALID_HANDLE_VALUE)
			FlushFileBuffers(si.hStdError);
	}
	/*
	* Disconnect all named pipes and close handles
	*/
	disconnect_close_pipe(si.hStdInput);
	disconnect_close_pipe(si.hStdOutput);
	disconnect_close_pipe(si.hStdError);
	return exit_code;
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
	run_client_cmd("change_this");
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
	g_hthreadMain = (HANDLE) _beginthreadex(0, 0,  main_thread, NULL, 0, &dwTID);
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
