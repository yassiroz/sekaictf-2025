CTR="$(forge create --rpc-url $1 --private-key 0x$2 src/Solve.sol:Solve --broadcast | tail -n 2 | head -n 1 |  cut -d " " -f 3)"
cast send --rpc-url $1 --private-key 0x$2 --gas-limit 30000000 $CTR "prime1()" > /dev/null
cast send --rpc-url $1 --private-key 0x$2 --gas-limit 30000000 $CTR "prime2()" > /dev/null
cast send --rpc-url $1 --private-key 0x$2 --gas-limit 28901887 $CTR "solve()" --legacy