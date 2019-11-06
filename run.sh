#!/bin/bash

konsole -e "python3 server.py" &
sleep 1
konsole -e "python3 turnstile.py" &
sleep 1
konsole -e "python3 turnstile.py --ti 127.0.0.1 --tport 9090" &
sleep 1
konsole -e "python3 client.py" &
