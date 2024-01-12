// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { Warehouse } from "../../src/Warehouse.sol";

import { Cast } from "../../src/libraries/Cast.sol";
import { Math } from "../../src/libraries/Math.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import { Address } from "../utils/Address.sol";
import { CommonBase } from "forge-std/Base.sol";
import { StdCheats } from "forge-std/StdCheats.sol";
import { StdUtils } from "forge-std/StdUtils.sol";

contract WarehouseHandler is CommonBase, StdCheats, StdUtils {
    using Math for uint256[];
    using Address for address;
    using Cast for address;

    Warehouse private warehouse;
    address public depositor;
    address[2] public tokens;

    address[5] private users;

    address private native;

    address private badActor;

    constructor(
        address _warehouse,
        address _depositor,
        address[2] memory _tokens,
        address[5] memory _users,
        address _badActor
    ) {
        warehouse = Warehouse(_warehouse);
        native = warehouse.NATIVE_TOKEN();
        depositor = _depositor;
        tokens = _tokens;
        users = _users;
        badActor = _badActor;
    }

    modifier mockDepositor() {
        vm.startPrank(depositor);
        _;
        vm.stopPrank();
    }

    modifier mockUser(uint256 _user) {
        _user = bound(_user, 0, users.length - 1);

        address user = users[_user];
        vm.startPrank(user);
        _;
        vm.stopPrank();
    }

    function deposit(uint256 _user, uint256 _token, uint192 _amount) public mockDepositor {
        _user = bound(_user, 0, users.length - 1);
        address user = users[_user];

        _token = bound(_token, 0, tokens.length - 1);
        address token = tokens[_token];

        if (token == native) {
            deal(depositor, _amount);
            warehouse.deposit{ value: _amount }(user, token, _amount);
        } else {
            deal(token, depositor, _amount);
            IERC20(token).approve(address(warehouse), _amount);
            warehouse.deposit(user, token, _amount);
        }
    }

    function deposit(uint256 _token, uint96[5] memory _amounts) public mockDepositor {
        (address[] memory owners, uint256[] memory amounts) = filter(users, _amounts);

        uint256 totalAmount = amounts.sumMem();

        _token = bound(_token, 0, tokens.length - 1);
        address token = tokens[_token];

        if (token == native) {
            deal(depositor, totalAmount);
            warehouse.deposit{ value: totalAmount }(owners, token, amounts);
        } else {
            deal(token, depositor, totalAmount);
            IERC20(token).approve(address(warehouse), totalAmount);
            warehouse.deposit(owners, token, amounts);
        }
    }

    function depositAfterTransfer(uint256 _user, uint256 _token, uint192 _amount) public mockDepositor {
        _user = bound(_user, 0, users.length - 1);
        address user = users[_user];

        _token = bound(_token, 0, tokens.length - 1);
        address token = tokens[_token];

        if (token == native) {
            return;
        } else {
            deal(token, depositor, _amount);
            IERC20(token).transfer(address(warehouse), _amount);
            warehouse.depositAfterTransfer(user, token, _amount);
        }
    }

    function depositAfterTransfer(uint256 _token, uint96[5] memory _amounts) public mockDepositor {
        _token = bound(_token, 0, tokens.length - 1);
        address token = tokens[_token];

        (address[] memory owners, uint256[] memory amounts) = filter(users, _amounts);

        uint256 totalAmount = amounts.sumMem();

        if (token == native) {
            return;
        } else {
            deal(token, depositor, totalAmount);
            IERC20(token).transfer(address(warehouse), totalAmount);
            warehouse.depositAfterTransfer(owners, token, amounts);
        }
    }

    function withdraw(uint256 _user, uint256 _token, uint256 _amount) public {
        _token = bound(_token, 0, tokens.length - 1);
        address token = tokens[_token];

        _user = bound(_user, 0, users.length - 1);
        address user = users[_user];
        _amount = bound(_amount, 0, warehouse.balanceOf(user, token.toUint256()));

        vm.prank(user);
        if (user == badActor && token == native) {
            vm.expectRevert();
        }
        warehouse.withdraw(token, _amount);
    }

    function withdrawForUser(uint256 _user, uint256 _token, uint256 _amount) public mockDepositor {
        _user = bound(_user, 0, users.length - 1);
        address user = users[_user];

        _token = bound(_token, 0, tokens.length - 1);
        address token = tokens[_token];

        _amount = bound(_amount, 0, warehouse.balanceOf(user, token.toUint256()));
        if (user == badActor && token == native) {
            vm.expectRevert();
        }
        warehouse.withdraw(user, token, _amount);
    }

    function withdrawWithIncentiveForUser(uint256 _user, uint256 _token, uint256 _amount, uint256 _withdrawer) public {
        _user = bound(_user, 0, users.length - 1);
        address user = users[_user];

        _token = bound(_token, 0, tokens.length - 1);
        address token = tokens[_token];

        _withdrawer = bound(_withdrawer, 0, users.length - 1);
        address withdrawer = users[_withdrawer];

        _amount = bound(_amount, 0, warehouse.balanceOf(user, token.toUint256()));
        vm.prank(withdrawer);
        if (user == badActor && token == native) {
            vm.expectRevert();
        } else if (withdrawer == badActor && token == native) {
            vm.expectRevert();
        }
        warehouse.withdrawWithIncentive(user, token, _amount, withdrawer);
    }

    function transfer(uint256 _sender, uint256 _receiver, uint256 _token, uint256 _amount) public mockUser(_sender) {
        _sender = bound(_sender, 0, users.length - 1);
        _receiver = bound(_receiver, 0, users.length - 1);

        address sender = users[_sender];
        address receiver = users[_receiver];

        _token = bound(_token, 0, tokens.length - 1);
        address token = tokens[_token];

        _amount = bound(_amount, 0, warehouse.balanceOf(sender, token.toUint256()));

        warehouse.transfer(receiver, token.toUint256(), _amount);
    }

    function transferFrom(
        uint256 _spender,
        uint256 _sender,
        uint256 _receiver,
        uint256 _token,
        uint256 _amount
    )
        public
        mockUser(_spender)
    {
        _spender = bound(_spender, 0, users.length - 1);
        _sender = bound(_sender, 0, users.length - 1);
        _receiver = bound(_receiver, 0, users.length - 1);

        address spender = users[_spender];
        address sender = users[_sender];
        address receiver = users[_receiver];

        _token = bound(_token, 0, tokens.length - 1);
        address token = tokens[_token];

        uint256 allowance = warehouse.allowance(sender, spender, token.toUint256());
        uint256 balance = warehouse.balanceOf(sender, token.toUint256());

        _amount = bound(_amount, 0, Math.min(allowance, balance));

        warehouse.transferFrom(sender, receiver, token.toUint256(), _amount);
    }

    function approve(uint256 _user, uint256 _token, uint256 _amount, uint256 _spender) public mockUser(_user) {
        _token = bound(_token, 0, tokens.length - 1);
        address token = tokens[_token];

        _spender = bound(_spender, 0, users.length - 1);
        address spender = users[_spender];

        warehouse.approve(spender, token.toUint256(), _amount);
    }

    function setOperator(uint256 _user, bool _approved, uint256 _operator) public mockUser(_user) {
        _operator = bound(_operator, 0, users.length - 1);
        address operator = users[_operator];

        warehouse.setOperator(operator, _approved);
    }

    function setWithdrawIncentive(uint256 _user, uint256 _incentive) public mockUser(_user) {
        _incentive = bound(_incentive, 0, warehouse.MAX_INCENTIVE());
        warehouse.setWithdrawIncentive(_incentive);
    }

    function filter(
        address[5] memory owners,
        uint96[5] memory amounts
    )
        private
        pure
        returns (address[] memory, uint256[] memory)
    {
        address[] memory _owners = new address[](5);
        uint256[] memory _amounts = new uint256[](5);

        uint256 index = 0;
        for (uint256 i = 0; i < 5; i++) {
            if (owners[i] != address(0)) {
                _owners[index] = owners[i];
                _amounts[index] = bound(amounts[i], 1, type(uint96).max);
                index++;
            }
        }

        return (_owners, _amounts);
    }
}
