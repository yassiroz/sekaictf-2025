clang++-20 -o luawasm -O2 --target=wasm32-wasi -lm -lc --sysroot=wasi-sysroot chal.cpp
./Wasynth/target/release/wasm2luajit luawasm > chal.lua