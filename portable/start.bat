@echo off
rem VulnBuster - uruchomienie reczne (okno konsoli = serwer; zamkniecie okna zatrzymuje aplikacje)
setlocal
cd /d "%~dp0"
echo VulnBuster: http://127.0.0.1:8443  (Ctrl+C zatrzymuje)
"%~dp0python\python.exe" "%~dp0app\run.py" --host 127.0.0.1 --port 8443 --data "%~dp0data\vulnbuster.json.enc" %*
pause
