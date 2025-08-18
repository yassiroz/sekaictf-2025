socat\socat.exe -T60 TCP-LISTEN:1337,reuseaddr,fork "EXEC:py server.py,pty,raw,stderr,echo=0"
pause