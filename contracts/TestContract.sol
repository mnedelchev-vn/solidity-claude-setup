// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";


contract TestContract {
    string public constant name = "TestContract";
    string public constant version = "1";
    address public immutable USDC;
    mapping(address => uint) public deposits;
    mapping (address => uint) public nonces;

    bytes32 public immutable DOMAIN_SEPARATOR;
    bytes32 public immutable DEPOSIT_TYPEHASH;

    error InvalidVerify();
    error InvalidNonce();
    error InvalidAmount();
    error InvalidDeadline();

    constructor(address USDC_, uint256 chainId_) {
        USDC = USDC_;
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes(name)),
            keccak256(bytes(version)),
            chainId_,
            address(this)
        ));
        DEPOSIT_TYPEHASH = keccak256("DepositWithPermit(uint256 amount,uint256 nonce,uint256 deadline)");
    }

    function deposit(uint256 amount) external {
        _deposit(msg.sender, amount);
    }

    function depositWithPermit(
        address signer,
        uint256 amount,
        uint256 nonce,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        if (block.timestamp > deadline) {
            revert InvalidDeadline();
        }
        if (nonce != nonces[signer]++) {
            revert InvalidNonce();
        }
        if (!verify(signer, v, r, s, keccak256(abi.encode(DEPOSIT_TYPEHASH, amount, nonce, deadline)))) {
            revert InvalidVerify();
        }
        _deposit(signer, amount);
    }

    function _deposit(address address_, uint256 amount) internal {
        if (amount == 0) {
            revert InvalidAmount();
        }
        deposits[address_] += amount;
        IERC20(USDC).transferFrom(address_, address(this), amount);
    }

    function verify(
        address signer,
        uint8 v,
        bytes32 r,
        bytes32 s,
        bytes32 encodedData
    ) public view returns (bool) {
        bytes32 digest =
            keccak256(abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                encodedData
            )
        );
        return signer == ECDSA.recover(digest, v, r, s);
    }

    function withdraw() external {
        uint amountToWithdraw = deposits[msg.sender];
        if (amountToWithdraw == 0) {
            revert InvalidAmount();
        }

        deposits[msg.sender] = 0;
        IERC20(USDC).transfer(msg.sender, amountToWithdraw);
    }
}