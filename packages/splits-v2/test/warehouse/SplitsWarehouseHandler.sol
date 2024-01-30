// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.18;

import { SplitsWarehouse } from "../../src/SplitsWarehouse.sol";

import { Cast } from "../../src/libraries/Cast.sol";
import { Math } from "../../src/libraries/Math.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import { Address } from "../utils/Address.sol";
import { CommonBase } from "forge-std/Base.sol";
import { StdCheats } from "forge-std/StdCheats.sol";
import { StdUtils } from "forge-std/StdUtils.sol";

contract SplitsWarehouseHandler is CommonBase, StdCheats, StdUtils {
    using Math for uint256[];
    using Address for address;
    using Cast for address;

    SplitsWarehouse private warehouse;
    address public depositor;
    address[2] public tokens;

    address[5] private users;

    address private native;

    address private badActor;

    mapping(address => uint256) public warehouseBalance;

    constructor(
        address _warehouse,
        address _depositor,
        address[2] memory _tokens,
        address[5] memory _users,
        address _badActor
    ) {
        warehouse = SplitsWarehouse(_warehouse);
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

        warehouseBalance[token] += _amount;
    }

    function withdraw(uint256 _user, uint256 _token) public {
        _token = bound(_token, 0, tokens.length - 1);
        address token = tokens[_token];

        _user = bound(_user, 0, users.length - 1);
        address user = users[_user];

        uint256 balance = warehouse.balanceOf(user, token.toUint256());

        if (balance == 0) {
            return;
        }

        vm.prank(user);
        if (user == badActor && token == native) {
            return;
        }
        warehouse.withdraw(user, token);

        warehouseBalance[token] -= balance - 1;
    }

    function withdraw(uint256 _user, uint256[2] memory _amounts, uint256 _withdrawer) public {
        _user = bound(_user, 0, users.length - 1);
        address user = users[_user];

        _withdrawer = bound(_withdrawer, 0, users.length - 1);
        address withdrawer = users[_withdrawer];

        address[] memory _tokens = new address[](2);
        uint256[] memory amounts = new uint256[](2);

        for (uint256 i = 0; i < 2; i++) {
            _tokens[i] = tokens[i];
            amounts[i] = bound(_amounts[i], 0, warehouse.balanceOf(user, _tokens[i].toUint256()));
        }

        (, bool paused) = warehouse.withdrawConfig(user);

        vm.prank(withdrawer);
        if (user == badActor || paused) {
            return;
        }
        warehouse.withdraw(user, _tokens, amounts, withdrawer);

        warehouseBalance[tokens[0]] -= amounts[0];
        warehouseBalance[tokens[1]] -= amounts[1];
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

    function setWithdrawConfig(uint256 _user, SplitsWarehouse.WithdrawConfig memory _config) public mockUser(_user) {
        warehouse.setWithdrawConfig(_config);
    }

    function batchTransfer(
        uint256 _sender,
        uint256[5] memory _receivers,
        uint256[5] memory _amounts,
        uint256 _token
    )
        public
        mockUser(_sender)
    {
        address[] memory receiverAddresses = new address[](5);
        uint256[] memory amounts = new uint256[](5);
        _sender = bound(_sender, 0, users.length - 1);

        uint256 balance = warehouse.balanceOf(users[_sender], _token);
        for (uint256 i = 0; i < 5; i++) {
            _receivers[i] = bound(_receivers[i], 0, users.length - 1);
            receiverAddresses[i] = users[_receivers[i]];

            amounts[i] = bound(_amounts[i], 0, balance);
            balance -= amounts[i];
        }

        _token = bound(_token, 0, tokens.length - 1);
        address token = tokens[_token];
        warehouse.batchTransfer(receiverAddresses, token, amounts);
    }

    function batchDeposit(
        uint256 _sender,
        uint256[5] memory _receivers,
        uint256[5] memory _amounts,
        uint256 _token
    )
        public
        mockUser(_sender)
    {
        address[] memory receiverAddresses = new address[](5);
        uint256[] memory amounts = new uint256[](5);
        _sender = bound(_sender, 0, users.length - 1);
        _token = bound(_token, 0, tokens.length - 1);
        address token = tokens[_token];

        uint256 balance = token == native ? address(this).balance : IERC20(tokens[_token]).balanceOf(address(this));
        uint256 amount = 0;
        for (uint256 i = 0; i < 5; i++) {
            _receivers[i] = bound(_receivers[i], 0, users.length - 1);
            receiverAddresses[i] = users[_receivers[i]];

            amounts[i] = bound(_amounts[i], 0, balance);
            balance -= amounts[i];
            amount += amounts[i];
        }

        if (token == native) {
            warehouse.batchDeposit{ value: amount }(receiverAddresses, token, amounts);
        } else {
            IERC20(token).approve(address(warehouse), amount);
            warehouse.batchDeposit(receiverAddresses, token, amounts);
        }

        warehouseBalance[token] += amount;
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
