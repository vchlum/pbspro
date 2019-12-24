REM Copyright (C) 1994-2019 Altair Engineering, Inc.
REM For more information, contact Altair at www.altair.com.
REM
REM This file is part of the PBS Professional ("PBS Pro") software.
REM
REM Open Source License Information:
REM
REM PBS Pro is free software. You can redistribute it and/or modify it under the
REM terms of the GNU Affero General Public License as published by the Free
REM Software Foundation, either version 3 of the License, or (at your option) any
REM later version.
REM
REM PBS Pro is distributed in the hope that it will be useful, but WITHOUT ANY
REM WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
REM FOR A PARTICULAR PURPOSE.
REM See the GNU Affero General Public License for more details.
REM
REM You should have received a copy of the GNU Affero General Public License
REM along with this program.  If not, see <http://www.gnu.org/licenses/>.
REM
REM Commercial License Information:
REM
REM For a copy of the commercial license terms and conditions,
REM go to: (http://www.pbspro.com/UserArea/agreement.html)
REM or contact the Altair Legal Department.
REM
REM Altair’s dual-license business model allows companies, individuals, and
REM organizations to create proprietary derivative works of PBS Pro and
REM distribute them - whether embedded or bundled with other software -
REM under a commercial license agreement.
REM
REM Use of Altair’s trademarks, including but not limited to "PBS™",
REM "PBS Professional®", and "PBS Pro™" and Altair’s logos is subject to Altair's
REM trademark licensing policies.

setlocal

if "%~1" == "" (
    echo Path to binaries directory require!
    exit /b 1
)

cd "%~dp0..\..\..\..\"
set WINBUILDDIR=%CD%\win_build
set PBS_EXECDIR=%CD%\PBS\exec
set PBS_SRCDIR=%CD%\pbspro
set BINARIESDIR=%~1
set BUILD_TYPE=Release
set BINARIESDIR_TYPE=
if "%~2"=="debug" (
    set BUILD_TYPE=Debug
    set BINARIESDIR_TYPE=_debug
)
if "%~2"=="Debug" (
    set BUILD_TYPE=Debug
    set BINARIESDIR_TYPE=_debug
)

cd "%~dp0"

2>nul rd /S /Q "%PBS_EXECDIR%"

echo Copying necessory files for PBS_EXEC\bin
for %%a in (
    "%WINBUILDDIR%\src\cmds\%BUILD_TYPE%\*.exe"
    "%WINBUILDDIR%\src\lib\Libpbspthread\%BUILD_TYPE%\Libpbspthread.dll"
    "%WINBUILDDIR%\src\tools\%BUILD_TYPE%\*.exe"
    "%PBS_SRCDIR%\src\cmds\scripts\*.bat"
) do (
    1>nul xcopy /Y /V /J "%%a" "%PBS_EXECDIR%\bin\"
    if not %ERRORLEVEL% == 0 (
        echo Failed to copy files from "%%a" to "%PBS_EXECDIR%\bin\"
        exit /b 1
    )
)

echo Copying necessory files for PBS_EXEC\sbin
for %%a in (
    "%WINBUILDDIR%\src\pbs_iff\%BUILD_TYPE%\*.exe"
    "%WINBUILDDIR%\src\pbs_mom\%BUILD_TYPE%\*.exe"
    "%WINBUILDDIR%\src\mom_rcp\%BUILD_TYPE%\*.exe"
) do (
    1>nul xcopy /Y /V /J "%%a" "%PBS_EXECDIR%\sbin\"
    if not %ERRORLEVEL% == 0 (
        echo Failed to copy files from "%%a" to "%PBS_EXECDIR%\sbin\"
        exit /b 1
    )
)

echo Copying necessory files for PBS_EXEC\etc
1>nul xcopy /Y /V /J "%PBS_SRCDIR%\src\cmds\scripts\win_postinstall.py" "%PBS_EXECDIR%\etc\"
if not %ERRORLEVEL% == 0 (
    echo Failed to copy files from "%PBS_SRCDIR%\src\cmds\scripts\win_postinstall.py" to "%PBS_EXECDIR%\etc\"
    exit /b 1
)

echo Copying necessory files for PBS_EXEC\include
for %%a in (
    "%PBS_SRCDIR%\src\include\pbs_error.h"
    "%PBS_SRCDIR%\src\include\pbs_ifl.h"
    "%PBS_SRCDIR%\src\include\rm.h"
    "%PBS_SRCDIR%\src\include\tm_.h"
    "%PBS_SRCDIR%\src\include\tm.h"
    "%PBS_SRCDIR%\src\include\win.h"
) do (
    1>nul xcopy /Y /V /J "%%a" "%PBS_EXECDIR%\include\"
    if not %ERRORLEVEL% == 0 (
        echo Failed to copy files from "%%a" to "%PBS_EXECDIR%\include\"
        exit /b 1
    )
)

echo Copying necessory files for PBS_EXEC\lib
1>nul xcopy /Y /V /J "%PBS_SRCDIR%\src\cmds\scripts\pbs_topologyinfo.py" "%PBS_EXECDIR%\lib\python\"
if not %ERRORLEVEL% == 0 (
    echo Failed to copy files from "%PBS_SRCDIR%\src\cmds\scripts\pbs_topologyinfo.py" to "%PBS_EXECDIR%\lib\python\"
    exit /b 1
)
1>nul xcopy /Y /V /J /S "%PBS_SRCDIR%\src\modules\python\pbs" "%PBS_EXECDIR%\lib\python\altair\pbs\"
if not %ERRORLEVEL% == 0 (
    echo Failed to copy files from "%PBS_SRCDIR%\src\modules\python\pbs" to "%PBS_EXECDIR%\lib\python\altair\pbs\"
    exit /b 1
)
1>nul xcopy /Y /V /J "%PBS_SRCDIR%\win_configure\projects\pbs_ifl.py" "%PBS_EXECDIR%\lib\python\altair\pbs\v1\"
if not %ERRORLEVEL% == 0 (
    echo Failed to copy files from "%PBS_SRCDIR%\win_configure\projects\pbs_ifl.py" to "%PBS_EXECDIR%\lib\python\altair\altair\v1\"
    exit /b 1
)
1>nul xcopy /Y /V /J /S "%BINARIESDIR%\python\Lib\*.*" "%PBS_EXECDIR%\lib\python\python3.6\"
if not %ERRORLEVEL% == 0 (
    echo Failed to copy files from "%BINARIESDIR%\python\Lib\" to "%PBS_EXECDIR%\lib\python\python3.6\"
    exit /b 1
)

for %%a in (
    "%WINBUILDDIR%\src\lib\Libattr\%BUILD_TYPE%\Libattr.lib"
    "%WINBUILDDIR%\src\lib\Libnet\%BUILD_TYPE%\Libnet.lib"
    "%WINBUILDDIR%\src\lib\Libpbs\%BUILD_TYPE%\Libpbs.lib"
    "%WINBUILDDIR%\src\lib\Libsite\%BUILD_TYPE%\Libsite.lib"
    "%WINBUILDDIR%\src\lib\Libwin\%BUILD_TYPE%\Libwin.lib"
) do (
    1>nul xcopy /Y /V /J "%%a" "%PBS_EXECDIR%\lib\"
    if not %ERRORLEVEL% == 0 (
        echo Failed to copy files from "%%a" to "%PBS_EXECDIR%\lib\"
        exit /b 1
    )
)

echo Copying necessory files for PBS_EXEC\unsupported
for %%a in (
    "%WINBUILDDIR%\src\unsupported\%BUILD_TYPE%\*.exe"
    "%PBS_SRCDIR%\src\unsupported\README"
    "%PBS_SRCDIR%\src\unsupported\*.pl"
    "%PBS_SRCDIR%\src\unsupported\*.py*"
) do (
    1>nul xcopy /Y /V /J "%%a" "%PBS_EXECDIR%\unsupported\"
    if not %ERRORLEVEL% == 0 (
        echo Failed to copy files from "%%a" to "%PBS_EXECDIR%\unsupported\"
        exit /b 1
    )
)

echo Copying necessory files for PBS_EXEC\python
1>nul xcopy /Y /V /J /S "%BINARIESDIR%\python" "%PBS_EXECDIR%\python\"
if not %ERRORLEVEL% == 0 (
    echo Failed to copy files from "%BINARIESDIR%\python" to "%PBS_EXECDIR%\python\"
    exit /b 1
)

if "%BUILD_TYPE%"=="Debug" (
    1>nul copy /B /Y "%BINARIESDIR%\python_debug\PCbuild\win32\python36_d.*" "%PBS_EXECDIR%\python\"
)

if exist "%BINARIESDIR%\python_x64" (
    echo Copying necessory files for PBS_EXEC\python_x64
    1>nul xcopy /Y /V /J /S "%BINARIESDIR%\python_x64" "%PBS_EXECDIR%\python_x64\"
    if not %ERRORLEVEL% == 0 (
        echo Failed to copy files from "%BINARIESDIR%\python_x64" to "%PBS_EXECDIR%\python_x64\"
        exit /b 1
    )
)

exit /b 0
