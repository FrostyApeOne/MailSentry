@echo off
setlocal
cd /d "%~dp0"
echo MailSentry Web UI: http://localhost:5080
echo Login: admin. Set Admin:Password to at least 16 characters in appsettings.json first.
echo Keep this window open. Press Ctrl+C to stop.
"%~dp0MailSentry.exe" --web --urls http://localhost:5080
exit /b %errorlevel%
