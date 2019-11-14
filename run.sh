#!/bin/bash

xterm -e "python3 server.py" &
sleep 1
xterm -e "python3 turnstile.py --cicle 2 --index $1 >> 5_3.txt" &
# sleep 1
# xterm -e "python3 turnstile.py --ti 127.0.0.1 --tport 9090 --cicle 2 --index $1 >> 5_2.txt" & 
sleep 1
xterm -e "python3 client.py --cicle 2 --index $1 " &

# sleep 4

# killall xterm

# xterm -e "cd /home/fernandes/Desktop/tcc-idgital-auth"
