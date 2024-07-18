#!/bin/sh
source /home/gyz/adkg/venv/bin/activate Python3.6
# N f B K
echo "start.sh <N> <F> <B> <K>"

# python3 run_trusted_key_gen.py --N $1 --f $2

killall python3
i=0
while [ "$i" -lt $1 ]; do
    echo "start node $i..."
    python3 run_socket_node.py --sid 'sidA' --id $i --N $1 --f $2 --B $3 --K $4 --l 5 --S 10 --T 5 --F 1000 --P "sufp" &
    i=$(( i + 1 ))
done
