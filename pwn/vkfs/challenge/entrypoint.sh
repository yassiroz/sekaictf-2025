#!/bin/bash
set -e

if [[ -f /root/flag.txt ]]; then
    cp /root/flag.txt /home/quandale/flag.txt
    chown quandale:quandale /home/quandale/flag.txt
fi

/usr/bin/supervisord -c /etc/supervisord.conf