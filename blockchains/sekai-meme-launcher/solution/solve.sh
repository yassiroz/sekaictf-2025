export MEME_MANAGER=$1
export PRIVATE_KEY=$2
export RPC_URL=$3

MEME_MANAGER=$MEME_MANAGER forge script script/Solve2.s.sol:Solve --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast --via-ir
