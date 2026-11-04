@echo off
setlocal
cd /d "%~dp0"
"%~dp0MailSentry.exe" --scan
exit /b %errorlevel%
