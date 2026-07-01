@echo off
REM Network packet sniffer launcher with LLDP/PROFINET support.
REM Must run as Administrator (raw socket access).
REM Usage:
REM   scan.bat                           -> list interfaces
REM   scan.bat "Ethernet 2"              -> capture LLDP, 10s timeout
REM   scan.bat "Ethernet 2" 20           -> capture LLDP, 20s timeout
REM   scan.bat "Ethernet 2" 20 lldp      -> capture LLDP, 20s
REM   scan.bat "Ethernet 2" 20 profinet  -> capture PROFINET, 20s
REM   scan.bat "Ethernet 2" 20 tcp       -> capture TCP, 20s
REM   scan.bat "Ethernet 2" 20 arp       -> ARP scan

setlocal
set IFACE=%~1
set TIMEOUT=%~2
set MODE=%~3

REM Check for admin privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: This script requires Administrator privileges.
    echo Right-click Command Prompt and select "Run as administrator"
    pause
    exit /b 1
)

REM List interfaces if no args
if "%IFACE%"=="" (
    echo No interface given. Listing available interfaces:
    python "%~dp0packet_capture.py" --list-ifaces
    pause
    exit /b 0
)

REM Default timeout
if "%TIMEOUT%"=="" set TIMEOUT=10

REM Default mode
if "%MODE%"=="" set MODE=lldp

REM Call packet_capture.py with parameters
if /I "%MODE%"=="lldp" (
    python "%~dp0packet_capture.py" -i "%IFACE%" -t %TIMEOUT% --lldp
) else if /I "%MODE%"=="profinet" (
    python "%~dp0packet_capture.py" -i "%IFACE%" -t %TIMEOUT% --profinet
) else if /I "%MODE%"=="tcp" (
    python "%~dp0packet_capture.py" -i "%IFACE%" -t %TIMEOUT% --tcp
) else if /I "%MODE%"=="arp" (
    python "%~dp0packet_capture.py" --arp "%IFACE%"
) else (
    echo Unknown mode: %MODE%
    echo Supported: lldp, profinet, tcp, arp
    pause
    exit /b 1
)

pause
