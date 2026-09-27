@echo off
rem Windows counterpart of bin/veloci, for machines without bash. Runs the
rem Veloci Redactor binary for this architecture from libexec\, falling back
rem to a veloci.exe installed elsewhere on PATH.
setlocal

set "ROOT=%~dp0.."

rem An x64 process on ARM64 Windows sees AMD64 here, and the real
rem architecture in PROCESSOR_ARCHITEW6432.
set "ARCH=%PROCESSOR_ARCHITEW6432%"
if not defined ARCH set "ARCH=%PROCESSOR_ARCHITECTURE%"

set "BIN="
if /i "%ARCH%"=="ARM64" set "BIN=%ROOT%\libexec\veloci-aarch64-pc-windows-msvc.exe"
if /i "%ARCH%"=="AMD64" set "BIN=%ROOT%\libexec\veloci-x86_64-pc-windows-msvc.exe"
if defined BIN if exist "%BIN%" goto run

rem No bundled binary: use another veloci on PATH. Only .exe is searched, so
rem this launcher can't find itself.
for /f "delims=" %%i in ('where veloci.exe 2^>nul') do (
  set "BIN=%%i"
  goto run
)

echo veloci: no binary for %ARCH% in %ROOT%\libexec, and none on PATH. 1>&2
echo Install it with: cargo install veloci-cli 1>&2
exit /b 127

:run
"%BIN%" %*
exit /b %ERRORLEVEL%
