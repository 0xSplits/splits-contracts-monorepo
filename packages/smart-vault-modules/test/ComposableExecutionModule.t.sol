// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { Test } from "forge-std/Test.sol";

import { ComposableExecutionModule } from "src/ComposableExecutionModule.sol";
import { Call, ISmartVault } from "src/interfaces/ISmartVault.sol";
import {
    ComposableExecution,
    Constraint,
    ConstraintType,
    InputParam,
    InputParamFetcherType,
    InputParamType,
    OutputParam,
    OutputParamFetcherType
} from "src/vendor/composability/ComposabilityDataTypes.sol";
import { ComposableExecutionLib } from "src/vendor/composability/ComposableExecutionLib.sol";
import { Storage } from "src/vendor/composability/Storage.sol";
import { ISmartVaultFactory, Signer } from "test/interfaces/ISmartVaultFactory.sol";

contract ComposableExecutionModuleTest is Test {
    /* -------------------------------------------------------------------------- */
    /*                                  CONSTANTS                                 */
    /* -------------------------------------------------------------------------- */

    /// @dev Deployed SmartVaultFactory on Base.
    ISmartVaultFactory constant FACTORY = ISmartVaultFactory(0x8E6Af8Ed94E87B4402D0272C5D6b0D47F0483e7C);

    /* -------------------------------------------------------------------------- */
    /*                                   ERRORS                                   */
    /* -------------------------------------------------------------------------- */

    error OnlyModule();

    /* -------------------------------------------------------------------------- */
    /*                                   EVENTS                                   */
    /* -------------------------------------------------------------------------- */

    event ExecutedComposable(address indexed account, uint256 executions);

    /* -------------------------------------------------------------------------- */
    /*                                    STATE                                   */
    /* -------------------------------------------------------------------------- */

    ISmartVault vault;
    ComposableExecutionModule module;
    Storage store;

    TestToken tokenIn;
    TestToken tokenOut;
    MockSwap swapPool;

    address owner;
    uint256 ownerKey;
    address recipient;

    /* -------------------------------------------------------------------------- */
    /*                                    SETUP                                   */
    /* -------------------------------------------------------------------------- */

    function setUp() public {
        vm.createSelectFork("base");

        (owner, ownerKey) = makeAddrAndKey("OWNER");
        recipient = makeAddr("RECIPIENT");

        module = new ComposableExecutionModule();
        store = new Storage();

        tokenIn = new TestToken();
        tokenOut = new TestToken();
        swapPool = new MockSwap(tokenIn, tokenOut);

        vault = _createVaultWithModule(0);
    }

    /* -------------------------------------------------------------------------- */
    /*                                   HELPERS                                  */
    /* -------------------------------------------------------------------------- */

    function _createVaultWithModule(uint256 salt_) internal returns (ISmartVault) {
        Signer[] memory signers = new Signer[](1);
        signers[0] = Signer({ slot1: bytes32(uint256(uint160(owner))), slot2: bytes32(0) });
        ISmartVault v = ISmartVault(FACTORY.createAccount(owner, signers, 1, salt_));
        vm.prank(address(v));
        v.enableModule(address(module));
        return v;
    }

    function _createVaultWithoutModule(uint256 salt_) internal returns (ISmartVault) {
        Signer[] memory signers = new Signer[](1);
        signers[0] = Signer({ slot1: bytes32(uint256(uint160(owner))), slot2: bytes32(0) });
        return ISmartVault(FACTORY.createAccount(owner, signers, 1, salt_));
    }

    function _noConstraints() internal pure returns (Constraint[] memory) {
        return new Constraint[](0);
    }

    function _constraint(ConstraintType type_, bytes memory referenceData_)
        internal
        pure
        returns (Constraint[] memory)
    {
        Constraint[] memory constraints = new Constraint[](1);
        constraints[0] = Constraint({ constraintType: type_, referenceData: referenceData_ });
        return constraints;
    }

    function _targetInput(address target_) internal pure returns (InputParam memory) {
        return InputParam({
            paramType: InputParamType.TARGET,
            fetcherType: InputParamFetcherType.RAW_BYTES,
            paramData: abi.encode(target_),
            constraints: _noConstraints()
        });
    }

    function _rawCalldataInput(bytes memory data_) internal pure returns (InputParam memory) {
        return InputParam({
            paramType: InputParamType.CALL_DATA,
            fetcherType: InputParamFetcherType.RAW_BYTES,
            paramData: data_,
            constraints: _noConstraints()
        });
    }

    function _balanceCalldataInput(
        address token_,
        address account_,
        Constraint[] memory constraints_
    )
        internal
        pure
        returns (InputParam memory)
    {
        return InputParam({
            paramType: InputParamType.CALL_DATA,
            fetcherType: InputParamFetcherType.BALANCE,
            paramData: abi.encodePacked(token_, account_),
            constraints: constraints_
        });
    }

    function _noOutputs() internal pure returns (OutputParam[] memory) {
        return new OutputParam[](0);
    }

    /// @dev A raw call as a single composable entry: selector as functionSig, target raw, args raw.
    function _rawEntry(address target_, bytes memory callData_) internal pure returns (ComposableExecution memory) {
        bytes4 sig;
        assembly {
            sig := mload(add(callData_, 0x20))
        }
        bytes memory args = new bytes(callData_.length - 4);
        for (uint256 i; i < args.length; i++) {
            args[i] = callData_[i + 4];
        }
        InputParam[] memory inputs = new InputParam[](2);
        inputs[0] = _targetInput(target_);
        inputs[1] = _rawCalldataInput(args);
        return ComposableExecution({ functionSig: sig, inputParams: inputs, outputParams: _noOutputs() });
    }

    /// @dev transfer(recipient, <runtime balance of token_ held by account_>) with optional constraints.
    function _transferAllEntry(
        address token_,
        address account_,
        address recipient_,
        Constraint[] memory constraints_
    )
        internal
        pure
        returns (ComposableExecution memory)
    {
        InputParam[] memory inputs = new InputParam[](3);
        inputs[0] = _targetInput(token_);
        inputs[1] = _rawCalldataInput(abi.encode(recipient_));
        inputs[2] = _balanceCalldataInput(token_, account_, constraints_);
        return ComposableExecution({
            functionSig: TestToken.transfer.selector, inputParams: inputs, outputParams: _noOutputs()
        });
    }

    /// @dev Approve + swap entries shared by the swap-shaped tests.
    function _swapEntries(uint256 amountIn_) internal view returns (ComposableExecution[] memory) {
        ComposableExecution[] memory entries = new ComposableExecution[](3);
        entries[0] = _rawEntry(address(tokenIn), abi.encodeCall(TestToken.approve, (address(swapPool), amountIn_)));
        entries[1] = _rawEntry(address(swapPool), abi.encodeCall(MockSwap.swap, (amountIn_)));
        return entries;
    }

    function _execute(ISmartVault vault_, ComposableExecution[] memory entries_) internal {
        vm.prank(address(vault_));
        module.executeComposable(entries_);
    }

    /* -------------------------------------------------------------------------- */
    /*                              LITERAL BATCHES                               */
    /* -------------------------------------------------------------------------- */

    function test_literalBatch_matchesExecuteFromModule() public {
        uint256 amount = 1000e18;
        ISmartVault plainVault = _createVaultWithModule(1);
        tokenIn.mint(address(vault), amount);
        tokenIn.mint(address(plainVault), amount);

        // Composable path with raw-bytes-only entries.
        ComposableExecution[] memory entries = new ComposableExecution[](2);
        entries[0] = _rawEntry(address(tokenIn), abi.encodeCall(TestToken.approve, (address(swapPool), amount)));
        entries[1] = _rawEntry(address(tokenIn), abi.encodeCall(TestToken.transfer, (recipient, amount)));

        vm.expectEmit(true, false, false, true, address(module));
        emit ExecutedComposable(address(vault), 2);
        _execute(vault, entries);

        // Same calls through the plain executeFromModule path.
        Call[] memory calls = new Call[](2);
        calls[0] = Call({
            target: address(tokenIn), value: 0, data: abi.encodeCall(TestToken.approve, (address(swapPool), amount))
        });
        calls[1] =
            Call({ target: address(tokenIn), value: 0, data: abi.encodeCall(TestToken.transfer, (recipient, amount)) });
        vm.prank(address(module));
        plainVault.executeFromModule(calls);

        // Both paths end in identical state.
        assertEq(tokenIn.balanceOf(address(vault)), 0);
        assertEq(tokenIn.balanceOf(address(plainVault)), 0);
        assertEq(tokenIn.balanceOf(recipient), 2 * amount);
        assertEq(tokenIn.allowance(address(vault), address(swapPool)), amount);
        assertEq(tokenIn.allowance(address(plainVault), address(swapPool)), amount);
    }

    /* -------------------------------------------------------------------------- */
    /*                               BALANCE FETCHER                              */
    /* -------------------------------------------------------------------------- */

    function test_balanceFetcher_swapThenTransferAll() public {
        uint256 amountIn = 1000e18;
        uint256 actualOut = 987e18;
        tokenIn.mint(address(vault), amountIn);
        swapPool.setNextOutput(actualOut);

        ComposableExecution[] memory entries = _swapEntries(amountIn);
        entries[2] = _transferAllEntry(address(tokenOut), address(vault), recipient, _noConstraints());

        _execute(vault, entries);

        // The full variable swap output reaches the recipient; nothing strands in the vault.
        assertEq(tokenOut.balanceOf(recipient), actualOut);
        assertEq(tokenOut.balanceOf(address(vault)), 0);
        assertEq(tokenIn.balanceOf(address(vault)), 0);
    }

    function testFuzz_balanceFetcher_swapThenTransferAll(uint256 actualOut_) public {
        actualOut_ = bound(actualOut_, 1, type(uint128).max);
        uint256 amountIn = 1000e18;
        tokenIn.mint(address(vault), amountIn);
        swapPool.setNextOutput(actualOut_);

        ComposableExecution[] memory entries = _swapEntries(amountIn);
        entries[2] = _transferAllEntry(address(tokenOut), address(vault), recipient, _noConstraints());

        _execute(vault, entries);

        assertEq(tokenOut.balanceOf(recipient), actualOut_);
        assertEq(tokenOut.balanceOf(address(vault)), 0);
    }

    function test_balanceFetcher_nativeEth() public {
        vm.deal(address(vault), 5 ether);

        // Send the vault's entire native balance: VALUE is fetched at execution time via the BALANCE fetcher.
        InputParam[] memory inputs = new InputParam[](2);
        inputs[0] = _targetInput(recipient);
        inputs[1] = InputParam({
            paramType: InputParamType.VALUE,
            fetcherType: InputParamFetcherType.BALANCE,
            paramData: abi.encodePacked(address(0), address(vault)),
            constraints: _noConstraints()
        });
        ComposableExecution[] memory entries = new ComposableExecution[](1);
        entries[0] = ComposableExecution({ functionSig: bytes4(0), inputParams: inputs, outputParams: _noOutputs() });

        _execute(vault, entries);

        assertEq(address(vault).balance, 0);
        assertEq(recipient.balance, 5 ether);
    }

    /* -------------------------------------------------------------------------- */
    /*                             STATIC_CALL FETCHER                            */
    /* -------------------------------------------------------------------------- */

    function test_staticCallFetcher() public {
        uint256 quoted = 777e18;
        tokenOut.mint(address(vault), 1000e18);
        swapPool.setNextOutput(quoted);

        // transfer(recipient, <MockSwap.nextOutput() read at execution time>)
        InputParam[] memory inputs = new InputParam[](3);
        inputs[0] = _targetInput(address(tokenOut));
        inputs[1] = _rawCalldataInput(abi.encode(recipient));
        inputs[2] = InputParam({
            paramType: InputParamType.CALL_DATA,
            fetcherType: InputParamFetcherType.STATIC_CALL,
            paramData: abi.encode(address(swapPool), abi.encodeCall(swapPool.nextOutput, ())),
            constraints: _noConstraints()
        });
        ComposableExecution[] memory entries = new ComposableExecution[](1);
        entries[0] = ComposableExecution({
            functionSig: TestToken.transfer.selector, inputParams: inputs, outputParams: _noOutputs()
        });

        _execute(vault, entries);

        assertEq(tokenOut.balanceOf(recipient), quoted);
        assertEq(tokenOut.balanceOf(address(vault)), 1000e18 - quoted);
    }

    /* -------------------------------------------------------------------------- */
    /*                                 CONSTRAINTS                                */
    /* -------------------------------------------------------------------------- */

    function test_constraintGTE_revertsAtomically() public {
        uint256 amountIn = 1000e18;
        uint256 minOut = 990e18;
        tokenIn.mint(address(vault), amountIn);
        swapPool.setNextOutput(minOut - 1);

        ComposableExecution[] memory entries = _swapEntries(amountIn);
        entries[2] = _transferAllEntry(
            address(tokenOut), address(vault), recipient, _constraint(ConstraintType.GTE, abi.encode(minOut))
        );

        vm.expectRevert(abi.encodeWithSelector(ComposableExecutionLib.ConstraintNotMet.selector, ConstraintType.GTE));
        _execute(vault, entries);

        // The whole batch reverted: the swap in entry 1 was rolled back too.
        assertEq(tokenIn.balanceOf(address(vault)), amountIn);
        assertEq(tokenOut.balanceOf(address(vault)), 0);
        assertEq(tokenOut.balanceOf(recipient), 0);
    }

    function test_constraintGTE_passes() public {
        uint256 amountIn = 1000e18;
        uint256 minOut = 990e18;
        tokenIn.mint(address(vault), amountIn);
        swapPool.setNextOutput(minOut);

        ComposableExecution[] memory entries = _swapEntries(amountIn);
        entries[2] = _transferAllEntry(
            address(tokenOut), address(vault), recipient, _constraint(ConstraintType.GTE, abi.encode(minOut))
        );

        _execute(vault, entries);

        assertEq(tokenOut.balanceOf(recipient), minOut);
    }

    function test_constraintEQ() public {
        tokenOut.mint(address(vault), 100e18);

        ComposableExecution[] memory pass = new ComposableExecution[](1);
        pass[0] = _transferAllEntry(
            address(tokenOut), address(vault), recipient, _constraint(ConstraintType.EQ, abi.encode(100e18))
        );
        _execute(vault, pass);
        assertEq(tokenOut.balanceOf(recipient), 100e18);

        tokenOut.mint(address(vault), 99e18);
        ComposableExecution[] memory fail = new ComposableExecution[](1);
        fail[0] = _transferAllEntry(
            address(tokenOut), address(vault), recipient, _constraint(ConstraintType.EQ, abi.encode(100e18))
        );
        vm.expectRevert(abi.encodeWithSelector(ComposableExecutionLib.ConstraintNotMet.selector, ConstraintType.EQ));
        _execute(vault, fail);
    }

    function test_constraintLTE() public {
        tokenOut.mint(address(vault), 100e18);

        ComposableExecution[] memory pass = new ComposableExecution[](1);
        pass[0] = _transferAllEntry(
            address(tokenOut), address(vault), recipient, _constraint(ConstraintType.LTE, abi.encode(100e18))
        );
        _execute(vault, pass);
        assertEq(tokenOut.balanceOf(recipient), 100e18);

        tokenOut.mint(address(vault), 101e18);
        ComposableExecution[] memory fail = new ComposableExecution[](1);
        fail[0] = _transferAllEntry(
            address(tokenOut), address(vault), recipient, _constraint(ConstraintType.LTE, abi.encode(100e18))
        );
        vm.expectRevert(abi.encodeWithSelector(ComposableExecutionLib.ConstraintNotMet.selector, ConstraintType.LTE));
        _execute(vault, fail);
    }

    function test_constraintIN() public {
        tokenOut.mint(address(vault), 100e18);

        ComposableExecution[] memory pass = new ComposableExecution[](1);
        pass[0] = _transferAllEntry(
            address(tokenOut),
            address(vault),
            recipient,
            _constraint(ConstraintType.IN, abi.encode(bytes32(uint256(50e18)), bytes32(uint256(150e18))))
        );
        _execute(vault, pass);
        assertEq(tokenOut.balanceOf(recipient), 100e18);

        tokenOut.mint(address(vault), 200e18);
        ComposableExecution[] memory fail = new ComposableExecution[](1);
        fail[0] = _transferAllEntry(
            address(tokenOut),
            address(vault),
            recipient,
            _constraint(ConstraintType.IN, abi.encode(bytes32(uint256(50e18)), bytes32(uint256(150e18))))
        );
        vm.expectRevert(abi.encodeWithSelector(ComposableExecutionLib.ConstraintNotMet.selector, ConstraintType.IN));
        _execute(vault, fail);
    }

    /* -------------------------------------------------------------------------- */
    /*                               OUTPUT CAPTURE                               */
    /* -------------------------------------------------------------------------- */

    function test_outputCapture_staticCall() public {
        uint256 amountIn = 1000e18;
        uint256 actualOut = 987e18;
        tokenIn.mint(address(vault), amountIn);
        swapPool.setNextOutput(actualOut);

        bytes32 slot = keccak256("test.swapOutput");

        // Swap, then capture the vault's post-swap tokenOut balance to Storage.
        OutputParam[] memory outputs = new OutputParam[](1);
        outputs[0] = OutputParam({
            fetcherType: OutputParamFetcherType.STATIC_CALL,
            paramData: abi.encode(
                uint256(1),
                address(tokenOut),
                abi.encodeCall(tokenOut.balanceOf, (address(vault))),
                address(store),
                slot
            )
        });

        ComposableExecution[] memory entries = _swapEntries(amountIn);
        entries[2] = ComposableExecution({
            functionSig: MockSwap.swap.selector, inputParams: new InputParam[](0), outputParams: outputs
        });
        // Entry 2 has no TARGET so it resolves to address(0): predicate/capture-only, no execution.

        _execute(vault, entries);

        bytes32 namespace = store.getNamespace(address(vault), address(module));
        bytes32 captured = store.readStorage(namespace, keccak256(abi.encodePacked(slot, uint256(0))));
        assertEq(uint256(captured), actualOut);

        // A second vault capturing under the same slot lands in its own namespace.
        ISmartVault vault2 = _createVaultWithModule(2);
        uint256 actualOut2 = 123e18;
        tokenIn.mint(address(vault2), amountIn);
        swapPool.setNextOutput(actualOut2);

        OutputParam[] memory outputs2 = new OutputParam[](1);
        outputs2[0] = OutputParam({
            fetcherType: OutputParamFetcherType.STATIC_CALL,
            paramData: abi.encode(
                uint256(1),
                address(tokenOut),
                abi.encodeCall(tokenOut.balanceOf, (address(vault2))),
                address(store),
                slot
            )
        });
        ComposableExecution[] memory entries2 = _swapEntries(amountIn);
        entries2[2] = ComposableExecution({
            functionSig: MockSwap.swap.selector, inputParams: new InputParam[](0), outputParams: outputs2
        });
        _execute(vault2, entries2);

        bytes32 namespace2 = store.getNamespace(address(vault2), address(module));
        assertEq(uint256(store.readStorage(namespace2, keccak256(abi.encodePacked(slot, uint256(0))))), actualOut2);
        // First vault's captured value is untouched.
        assertEq(uint256(store.readStorage(namespace, keccak256(abi.encodePacked(slot, uint256(0))))), actualOut);
    }

    function test_outputCapture_execResult_reverts() public {
        OutputParam[] memory outputs = new OutputParam[](1);
        outputs[0] = OutputParam({
            fetcherType: OutputParamFetcherType.EXEC_RESULT,
            paramData: abi.encode(uint256(1), address(store), bytes32(0))
        });

        ComposableExecution[] memory entries = new ComposableExecution[](1);
        entries[0] = ComposableExecution({
            functionSig: TestToken.transfer.selector, inputParams: new InputParam[](0), outputParams: outputs
        });

        vm.expectRevert(ComposableExecutionLib.ExecResultNotSupported.selector);
        _execute(vault, entries);
    }

    /* -------------------------------------------------------------------------- */
    /*                                ACCESS CONTROL                              */
    /* -------------------------------------------------------------------------- */

    function test_revertsWhen_moduleNotEnabled() public {
        ISmartVault bareVault = _createVaultWithoutModule(3);
        tokenOut.mint(address(bareVault), 100e18);

        ComposableExecution[] memory entries = new ComposableExecution[](1);
        entries[0] = _transferAllEntry(address(tokenOut), address(bareVault), recipient, _noConstraints());

        vm.expectRevert(OnlyModule.selector);
        _execute(bareVault, entries);

        assertEq(tokenOut.balanceOf(address(bareVault)), 100e18);
    }

    function test_attackerCannotExecuteForOtherVault() public {
        tokenOut.mint(address(vault), 100e18);
        address attacker = makeAddr("ATTACKER");

        // Entries shaped to drain the vault's tokenOut. The module executes for msg.sender only, so the
        // loop-back targets the attacker address, which has no executeFromModule.
        ComposableExecution[] memory entries = new ComposableExecution[](1);
        entries[0] = _transferAllEntry(address(tokenOut), address(vault), attacker, _noConstraints());

        vm.prank(attacker);
        vm.expectRevert();
        module.executeComposable(entries);

        assertEq(tokenOut.balanceOf(address(vault)), 100e18);
        assertEq(tokenOut.balanceOf(attacker), 0);
    }

    function test_revertsWhen_moduleDisabled() public {
        ISmartVault v = _createVaultWithModule(4);
        tokenOut.mint(address(v), 100e18);

        ComposableExecution[] memory entries = new ComposableExecution[](1);
        entries[0] = _transferAllEntry(address(tokenOut), address(v), recipient, _noConstraints());
        _execute(v, entries);
        assertEq(tokenOut.balanceOf(recipient), 100e18);

        vm.prank(address(v));
        v.disableModule(address(module));

        tokenOut.mint(address(v), 50e18);
        ComposableExecution[] memory entries2 = new ComposableExecution[](1);
        entries2[0] = _transferAllEntry(address(tokenOut), address(v), recipient, _noConstraints());

        vm.expectRevert(OnlyModule.selector);
        _execute(v, entries2);

        assertEq(tokenOut.balanceOf(address(v)), 50e18);
    }
}

/// @dev Minimal mintable ERC-20 for exercising the module.
contract TestToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to_, uint256 amount_) external {
        balanceOf[to_] += amount_;
    }

    function transfer(address to_, uint256 amount_) external returns (bool) {
        balanceOf[msg.sender] -= amount_;
        balanceOf[to_] += amount_;
        return true;
    }

    function transferFrom(address from_, address to_, uint256 amount_) external returns (bool) {
        allowance[from_][msg.sender] -= amount_;
        balanceOf[from_] -= amount_;
        balanceOf[to_] += amount_;
        return true;
    }

    function approve(address spender_, uint256 amount_) external returns (bool) {
        allowance[msg.sender][spender_] = amount_;
        return true;
    }
}

/// @dev Swap stub whose output is configured per test, modelling quote-time vs execution-time drift.
contract MockSwap {
    TestToken public immutable TOKEN_IN;
    TestToken public immutable TOKEN_OUT;

    uint256 public nextOutput;

    constructor(TestToken tokenIn_, TestToken tokenOut_) {
        TOKEN_IN = tokenIn_;
        TOKEN_OUT = tokenOut_;
    }

    function setNextOutput(uint256 nextOutput_) external {
        nextOutput = nextOutput_;
    }

    function swap(uint256 amountIn_) external {
        TOKEN_IN.transferFrom(msg.sender, address(this), amountIn_);
        TOKEN_OUT.mint(msg.sender, nextOutput);
    }
}
