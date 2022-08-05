// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "./ManagerAccessControl.sol";

/// @notice Bridge where any token can be exchanged
contract TokenBridge is ManagerAccessControl {
    /// @notice It is a data type to determine whether a token is registered or not
    enum TokenStatus {
        NotRegistered,
        Registered
    }

    /// @notice Information about registered a token
    struct TokenInfo {
        ERC20 token;
        address tokenAddress;
        TokenStatus status;
        mapping(address => uint256) liquidBalance;
    }

    /// @notice Information about registered tokens
    mapping(bytes32 => TokenInfo) public tokens;

    /// @notice Events that occur when a new token is registered
    event TokenRegistered(bytes32 tokenId, address tokenAddress);

    uint256 private depositTimeLock;
    uint256 private withdrawTimeLock;

    constructor(uint256 _timeLock) {
        depositTimeLock = _timeLock * 2;
        withdrawTimeLock = _timeLock;
    }

    /// @notice Information about registered tokens
    /// @param _tokenId Unique ID of the token
    /// @param _tokenAddress The address of the smart contact of the token
    function registerToken(bytes32 _tokenId, address _tokenAddress) external onlyManager {
        require(_tokenAddress != address(0));
        ERC20 token = ERC20(_tokenAddress);

        bytes32 tokenId = sha256(abi.encodePacked(address(this), token.name(), token.symbol()));

        require(tokenId == _tokenId);

        require(tokens[_tokenId].status == TokenStatus.NotRegistered);

        tokens[_tokenId].token = token;
        tokens[_tokenId].tokenAddress = _tokenAddress;
        tokens[_tokenId].status = TokenStatus.Registered;

        emit TokenRegistered(_tokenId, _tokenAddress);
    }

    event ChangeTimeLock(uint256 _timeLock);

    /// @notice Change time lock
    /// @param _timeLock new time lock
    function changeTimeLock(uint256 _timeLock) public onlyManager {
        depositTimeLock = _timeLock * 2;
        withdrawTimeLock = _timeLock;
        emit ChangeTimeLock(depositTimeLock);
    }

    enum States {
        INVALID,
        OPEN,
        CLOSED,
        EXPIRED
    }

    struct DepositLockBox {
        bytes32 tokenId;
        uint256 timeLock;
        uint256 amount;
        address traderAddress;
        address withdrawAddress;
        bytes32 secretLock;
        bytes secretKey;
        uint256 createTimestamp;
    }

    mapping(bytes32 => DepositLockBox) private depositBoxes;
    mapping(bytes32 => States) private depositBoxStates;

    event OpenDeposit(bytes32 _boxID, bytes32 _secretLock);
    event ExpireDeposit(bytes32 _boxID);
    event CloseDeposit(bytes32 _boxID, bytes _secretKey);

    modifier onlyInvalidDepositBoxes(bytes32 _boxID) {
        require(depositBoxStates[_boxID] == States.INVALID, "Already open deposit.|ALREADY_OPEN_DEPOSIT");
        _;
    }

    modifier onlyOpenDepositBoxes(bytes32 _boxID) {
        require(depositBoxStates[_boxID] == States.OPEN, "Not open deposit.|NOT_OPEN_DEPOSIT");
        _;
    }

    modifier onlyClosedDepositBoxes(bytes32 _boxID) {
        require(depositBoxStates[_boxID] == States.CLOSED, "Not close deposit.|NOT_CLOSE_DEPOSIT");
        _;
    }

    modifier onlyExpirableDepositBoxes(bytes32 _boxID) {
        require(
            depositBoxes[_boxID].timeLock + depositBoxes[_boxID].createTimestamp <= block.timestamp,
            "Not expired deposit.|NOT_EXPIRED_DEPOSIT"
        );
        _;
    }

    modifier onlyWithSecretKeyDepositBoxes(bytes32 _boxID, bytes memory _secretKey) {
        require(depositBoxes[_boxID].secretLock == sha256(_secretKey), "Not key deposit.|NOT_KEY_DEPOSIT");
        _;
    }

    /// @notice Open the deposit lock box
    function openDeposit(
        bytes32 _tokenId,
        bytes32 _boxID,
        uint256 _amount,
        address _withdrawAddress,
        bytes32 _secretLock
    ) public onlyInvalidDepositBoxes(_boxID) {
        require(_withdrawAddress != address(0));

        IERC20 token = tokens[_tokenId].token;

        require(tokens[_tokenId].status == TokenStatus.Registered, "Token is not registered");
        require(
            _amount <= token.allowance(msg.sender, address(this)),
            "Not allowed open deposit.|NOT_ALLOWED_OPEN_DEPOSIT"
        );
        require(
            token.transferFrom(msg.sender, address(this), _amount),
            "Error transfer open deposit.|ERROR_TRANSFER_OPEN_DEPOSIT"
        );

        // Store the details of the box.
        DepositLockBox memory box = DepositLockBox({
            tokenId: _tokenId,
            timeLock: depositTimeLock,
            amount: _amount,
            traderAddress: msg.sender,
            withdrawAddress: _withdrawAddress,
            secretLock: _secretLock,
            secretKey: new bytes(0),
            createTimestamp: block.timestamp
        });

        depositBoxes[_boxID] = box;
        depositBoxStates[_boxID] = States.OPEN;
        emit OpenDeposit(_boxID, _secretLock);
    }

    /// @notice Close the deposit lock box
    function closeDeposit(bytes32 _boxID, bytes memory _secretKey)
        public
        onlyOpenDepositBoxes(_boxID)
        onlyWithSecretKeyDepositBoxes(_boxID, _secretKey)
    {
        depositBoxes[_boxID].secretKey = _secretKey;
        depositBoxStates[_boxID] = States.CLOSED;

        emit CloseDeposit(_boxID, _secretKey);
    }

    /// @notice Expire the deposit lock box
    function expireDeposit(bytes32 _boxID) public onlyOpenDepositBoxes(_boxID) onlyExpirableDepositBoxes(_boxID) {
        DepositLockBox memory box = depositBoxes[_boxID];
        depositBoxStates[_boxID] = States.EXPIRED;
        IERC20 token = tokens[depositBoxes[_boxID].tokenId].token;
        require(
            token.transfer(box.traderAddress, box.amount),
            "Error transfer expire deposit.|ERROR_TRANSFER_EXPIRE_DEPOSIT"
        );

        emit ExpireDeposit(_boxID);
    }

    /// @notice Check the deposit lock box
    function checkDeposit(bytes32 _boxID)
        public
        view
        returns (
            States states,
            bytes32 tokenId,
            uint256 timeLock,
            uint256 amount,
            address traderAddress,
            address withdrawAddress,
            bytes32 secretLock,
            uint256 createTimestamp
        )
    {
        DepositLockBox memory box = depositBoxes[_boxID];
        States state = depositBoxStates[_boxID];
        return (
            state,
            box.tokenId,
            box.timeLock,
            box.amount,
            box.traderAddress,
            box.withdrawAddress,
            box.secretLock,
            box.createTimestamp
        );
    }

    /// @notice Check the secret key of the deposit lock box
    function checkSecretKeyDeposit(bytes32 _boxID)
        public
        view
        onlyClosedDepositBoxes(_boxID)
        returns (bytes memory secretKey)
    {
        DepositLockBox memory box = depositBoxes[_boxID];
        return box.secretKey;
    }

    struct WithdrawLockBox {
        bytes32 tokenId;
        uint256 timeLock;
        uint256 amount;
        address traderAddress;
        address withdrawAddress;
        bytes32 secretLock;
        bytes secretKey;
        uint256 createTimestamp;
    }

    mapping(bytes32 => WithdrawLockBox) private withdrawBoxes;
    mapping(bytes32 => States) private withdrawBoxStates;

    event OpenWithdraw(bytes32 _boxID, bytes32 _secretLock);
    event ExpireWithdraw(bytes32 _boxID);
    event CloseWithdraw(bytes32 _boxID, bytes _secretKey);

    modifier onlyInvalidWithdrawBoxes(bytes32 _boxID) {
        require(withdrawBoxStates[_boxID] == States.INVALID, "Already open withdraw.|ALREADY_OPEN_WITHDRAW");
        _;
    }

    modifier onlyOpenWithdrawBoxes(bytes32 _boxID) {
        require(withdrawBoxStates[_boxID] == States.OPEN, "Not open withdraw.|NOT_OPEN_WITHDRAW");
        _;
    }

    modifier onlyClosedWithdrawBoxes(bytes32 _boxID) {
        require(withdrawBoxStates[_boxID] == States.CLOSED, "Not close withdraw.|NOT_CLOSE_WITHDRAW");
        _;
    }

    modifier onlyExpirableWithdrawBoxes(bytes32 _boxID) {
        require(
            withdrawBoxes[_boxID].timeLock + withdrawBoxes[_boxID].createTimestamp <= block.timestamp,
            "Not expired withdraw.|NOT_EXPIRED_WITHDRAW"
        );
        _;
    }

    modifier onlyWithSecretKeyWithdrawBoxes(bytes32 _boxID, bytes memory _secretKey) {
        require(withdrawBoxes[_boxID].secretLock == sha256(_secretKey), "Not key withdraw.|NOT_KEY_WITHDRAW");
        _;
    }

    /// @notice Open the withdraw lock box
    function openWithdraw(
        bytes32 _tokenId,
        bytes32 _boxID,
        uint256 _amount,
        address _traderAddress,
        address _withdrawAddress,
        bytes32 _secretLock
    ) public onlyManager onlyInvalidWithdrawBoxes(_boxID) {
        require(_traderAddress != address(0));
        require(_withdrawAddress != address(0));

        IERC20 token = tokens[_tokenId].token;

        require(tokens[_tokenId].status == TokenStatus.Registered, "Token is not registered");

        // Transfer value from the ERC20 trader to this contract.
        require(_amount <= token.balanceOf(address(this)), "Insufficient liquidity.|INSUFFICIENT_LIQUIDITY");

        // Store the details of the box.
        WithdrawLockBox memory box = WithdrawLockBox({
            tokenId: _tokenId,
            timeLock: withdrawTimeLock,
            amount: _amount,
            traderAddress: _traderAddress,
            withdrawAddress: _withdrawAddress,
            secretLock: _secretLock,
            secretKey: new bytes(0),
            createTimestamp: block.timestamp
        });
        withdrawBoxes[_boxID] = box;
        withdrawBoxStates[_boxID] = States.OPEN;
        emit OpenWithdraw(_boxID, _secretLock);
    }

    /// @notice Close the withdraw lock box
    function closeWithdraw(bytes32 _boxID, bytes memory _secretKey)
        public
        onlyOpenWithdrawBoxes(_boxID)
        onlyWithSecretKeyWithdrawBoxes(_boxID, _secretKey)
    {
        WithdrawLockBox memory box = withdrawBoxes[_boxID];
        IERC20 token = tokens[box.tokenId].token;

        require(
            box.amount <= token.balanceOf(address(this)),
            "Insufficient liquidity close withdraw.|INSUFFICIENT_LIQUIDITY_CLOSE_WITHDRAW"
        );

        // Close the box.
        withdrawBoxes[_boxID].secretKey = _secretKey;
        withdrawBoxStates[_boxID] = States.CLOSED;

        // Transfer the ERC20 funds from this contract to the withdrawing trader.
        token.transfer(box.withdrawAddress, box.amount);

        emit CloseWithdraw(_boxID, _secretKey);
    }

    /// @notice Expire the withdraw lock box
    function expireWithdraw(bytes32 _boxID) public onlyOpenWithdrawBoxes(_boxID) onlyExpirableWithdrawBoxes(_boxID) {
        // Expire the box.
        withdrawBoxStates[_boxID] = States.EXPIRED;

        emit ExpireWithdraw(_boxID);
    }

    /// @notice Check the withdraw lock box
    function checkWithdraw(bytes32 _boxID)
        public
        view
        returns (
            States states,
            bytes32 tokenId,
            uint256 timeLock,
            uint256 amount,
            address traderAddress,
            address withdrawAddress,
            bytes32 secretLock,
            uint256 createTimestamp
        )
    {
        WithdrawLockBox memory box = withdrawBoxes[_boxID];
        States state = withdrawBoxStates[_boxID];
        return (
            state,
            box.tokenId,
            box.timeLock,
            box.amount,
            box.traderAddress,
            box.withdrawAddress,
            box.secretLock,
            box.createTimestamp
        );
    }

    /// @notice Check the secret key of the withdraw lock box
    function checkSecretKeyWithdraw(bytes32 _boxID)
        public
        view
        onlyClosedWithdrawBoxes(_boxID)
        returns (bytes memory secretKey)
    {
        WithdrawLockBox memory box = withdrawBoxes[_boxID];
        return box.secretKey;
    }

    event IncreasedLiquidity(bytes32 tokenId, address provider, uint256 amount);
    event DecreasedLiquidity(bytes32 tokenId, address provider, uint256 amount);

    function increaseLiquidity(
        bytes32 _tokenId,
        address _provider,
        uint256 _amount
    ) public {
        require(_amount > 0, "Invalid amount increase");
        TokenStatus status = tokens[_tokenId].status;
        ERC20 token = tokens[_tokenId].token;
        require(status == TokenStatus.Registered);

        require(_amount <= token.allowance(_provider, address(this)), "Not allowance increase liquidity");

        token.transferFrom(_provider, address(this), _amount);
        uint256 liquid = tokens[_tokenId].liquidBalance[_provider];
        tokens[_tokenId].liquidBalance[_provider] = liquid + _amount;
        emit IncreasedLiquidity(_tokenId, _provider, _amount);
    }

    function decreaseLiquidity(bytes32 _tokenId, uint256 _amount) public {
        require(_amount > 0, "Invalid amount decrease");
        TokenStatus status = tokens[_tokenId].status;
        ERC20 token = tokens[_tokenId].token;
        require(status == TokenStatus.Registered);

        uint256 liquid = tokens[_tokenId].liquidBalance[msg.sender];
        require(_amount <= liquid, "Insufficient user's liquidity");
        require(_amount <= token.balanceOf(address(this)), "The liquidity is insufficient");
        tokens[_tokenId].liquidBalance[msg.sender] = liquid - _amount;
        token.transfer(msg.sender, _amount);
        emit DecreasedLiquidity(_tokenId, msg.sender, _amount);
    }

    function balanceOfLiquidity(bytes32 _tokenId, address _provider) public view returns (uint256 amount) {
        require(tokens[_tokenId].status == TokenStatus.Registered);
        return tokens[_tokenId].liquidBalance[_provider];
    }
}
