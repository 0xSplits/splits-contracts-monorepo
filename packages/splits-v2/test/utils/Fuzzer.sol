// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

contract Fuzzer {
    error LengthMismatch();

    function fuzzMultipleOwnerDeposits(
        address[5] memory _owners,
        uint96[5] memory _amounts
    )
        public
        pure
        returns (address[] memory owners, uint256[] memory amounts)
    {
        if (_owners.length != _amounts.length) {
            revert LengthMismatch();
        }

        owners = new address[](_owners.length);
        amounts = new uint256[](_amounts.length);
        for (uint256 i = 0; i < _owners.length; i++) {
            (address owner, uint256 amount) = fuzzOwnerDeposit(_owners[i], _amounts[i]);
            owners[i] = owner;
            amounts[i] = amount;
        }

        return (owners, amounts);
    }

    function fuzzOwnerDeposit(address _owner, uint96 _amount) public pure returns (address owner, uint256 amount) {
        owner = _owner;
        amount = _amount;
        if (_amount == 0) amount = uint256(uint160(_owner)) + 1;
        if (_owner == address(0)) owner = address(uint160(amount + 1));
    }
}
