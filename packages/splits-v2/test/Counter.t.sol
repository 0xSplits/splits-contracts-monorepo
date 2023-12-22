// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import { PRBTest } from "@prb/test/PRBTest.sol";
import { Counter } from "../src/Counter.sol";

contract CounterTest is PRBTest {
    Counter public counter;

    function setUp() public {
        counter = new Counter();
        counter.setNumber(0);
    }

    function test_Increment() public {
        counter.increment();
        assertEq(counter.number(), 1);
    }

    function testFuzz_SetNumber(uint256 x) public {
        counter.setNumber(x);
        assertEq(counter.number(), x);
    }
}
