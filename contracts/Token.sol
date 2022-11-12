// SPDX-License-Identifier: MIT
pragma solidity =0.8.17;

import "./extensions/ERC20Burnable.sol";
import "./extensions/ERC20Pausable.sol";
import "./access/AccessControlEnumerable.sol";

/**
    ERC20 token for tecra.space project
 */
contract TecraCoin is ERC20Pausable, ERC20Burnable, AccessControlEnumerable {
    /**
        Contract constructor
        @param owner address of contract owner/admin
        @param mintMultisig number of signatures needed for minting
        @param amount amount of tokens minted on deploy
        @param _name token name
        @param _symbol token symbol
     */
    constructor(
        address owner,
        uint256 mintMultisig,
        uint256 amount,
        uint256 maxSupply,
        string memory _name,
        string memory _symbol
    ) ERC20(_name, _symbol) {
        // sanity checks
        if (owner == address(0)) revert();
        if (mintMultisig == 0) revert();
        if (amount == 0) revert();
        if (maxSupply == 0) revert();
        if (bytes(_name).length < 3) revert();
        if (bytes(_symbol).length < 2) revert();

        _grantRole(DEFAULT_ADMIN_ROLE, owner);
        _signaturesNeeded = mintMultisig;
        _mint(owner, amount);
        _maxSupply = maxSupply;
    }

    //
    // Constants
    //

    /// Hash of pauser role
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    /// Hash of minter role
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    /// Blacklister role hash
    bytes32 public constant BLACKLISTER_ROLE = keccak256("BLACKLISTER_ROLE");
    /// Burner role hash
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");

    //
    // Events
    //

    /**
        Emitted on adding to blacklist
        @param user added
        @param timestamp of adding to blacklist
     */
    event BlacklistAdded(address indexed user, uint256 timestamp);

    /**
        Emitted on removing from blacklist
        @param user removed
        @param timestamp of removing from blacklist
     */
    event BlacklistRemoved(address indexed user, uint256 timestamp);
    /**
        Emit on creating mint request by 1st minter
        @param user target address
        @param amount of tokens to be minted
     */
    event MintRequested(address indexed user, uint256 amount);

    /**
        Emitted on signature under request
        @param signer address of minter that sign request
        @param index of request in storage
     */
    event MintSigned(address indexed signer, uint256 index);

    //
    // Errors
    //

    /// Thrown when want add to blacklist same address again
    error AlreadyOnBlacklist();
    /// Thrown when try remove from blacklist not-blacklisted user
    error NotOnBlacklist();
    /// Thrown on transfer if sender is blacklisted
    error SenderOnBlacklist();
    /// Thrown on transfer if receiver is blacklisted
    error ReceiverOnBlacklist();
    /// Thrown when try to burn from empty address
    error NothingToBurn();

    /// Thrown on request or mint that is over supply
    error MintOverSupply();
    /// Thrown on duplicate signature
    error AlreadySigned();
    /// Thrown on duplicate mint try
    error AlreadyMinted();
    /// Thrown on request to mint 0 tokens
    error MintAmountZero();
    /// Thrown when sign non-existent request
    error WrongMintIndex();

    //
    // Storage
    //

    // mapping of blacklist add timestamps
    mapping(address => uint256) internal _blacklist;
    // How many signatures are need after request
    uint256 internal immutable _signaturesNeeded;
    // Total max supply of tokens in existence
    uint256 internal immutable _maxSupply;

    // requests storage
    mapping(uint256 => MintRequest) _requests;
    // mint counter
    uint256 internal _mints;

    //
    // Structs
    //

    /**
        Request struct
        @param user address of mint target
        @param amount of tokens to mint
        @param count how many signatures are done
        @param signed storage of signature markers
     */
    struct MintRequest {
        address user;
        uint256 amount;
        uint256 count;
        mapping(address => bool) signed;
    }

    //
    // External functions
    //
    function pause() public onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() public onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    //
    // Blacklist
    //

    /**
        Add or remove user from blacklist
        @param user address of the user
        @param blacklist true=add to blacklist, false=remove from blacklist
     */
    function blacklistAddress(address user, bool blacklist)
        external
        onlyRole(BLACKLISTER_ROLE)
    {
        if (blacklist) {
            if (_blacklist[user] > 0) revert AlreadyOnBlacklist();
            _blacklist[user] = block.timestamp;
            emit BlacklistAdded(user, block.timestamp);
        } else {
            if (_blacklist[user] == 0) revert NotOnBlacklist();
            delete _blacklist[user];
            emit BlacklistRemoved(user, block.timestamp);
        }
    }

    /**
        Funds can be destroyed from blacklisted address
        @param user address on blacklist to be burned
    */
    function burnBlackFunds(address user) external onlyRole(BURNER_ROLE) {
        if (_blacklist[user] == 0) revert NotOnBlacklist();
        uint256 balance = _balances[user];
        if (balance == 0) revert NothingToBurn();
        delete _balances[user];
        _totalSupply -= balance;
        emit Transfer(user, address(0), balance);
    }

    //
    // Multisig mint
    //

    /**
        Create mint request by minter
        @param user mint target address
        @param amount of tokens to be minted
     */
    function requestMint(address user, uint256 amount)
        external
        onlyRole(MINTER_ROLE)
    {
        if (user == address(0)) revert MintToTheZeroAddress();
        if (amount == 0) revert MintAmountZero();
        if (_blacklist[user] > 0) revert ReceiverOnBlacklist();
        if (amount + _totalSupply > _maxSupply) revert MintOverSupply();
        uint256 idx = _mints++;
        MintRequest storage m = _requests[idx];
        m.user = user;
        m.amount = amount;
        m.signed[msg.sender] = true;
        emit MintRequested(user, amount);
    }

    /**
        Sign mint under index.
        If last required signature - execute mint.
        @param idx index of request
     */
    function signMint(uint256 idx) external onlyRole(MINTER_ROLE) {
        MintRequest storage m = _requests[idx];
        if (m.signed[msg.sender]) revert AlreadySigned();
        if (m.user == address(0)) revert WrongMintIndex();
        m.signed[msg.sender] = true;
        uint256 signatures = ++m.count;
        if (signatures >= _signaturesNeeded) {
            uint256 amt = m.amount;
            if (amt == 0) revert AlreadyMinted();
            if (amt + _totalSupply > _maxSupply) revert MintOverSupply();
            // zero amount in storage aka "is minted"
            m.amount = 0;
            // we can mint
            _mint(m.user, amt);
        }
        emit MintSigned(msg.sender, idx);
    }

    //
    // Internal functions
    //

    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 amount
    ) internal override(ERC20, ERC20Pausable) {
        if (_blacklist[from] > 0) revert SenderOnBlacklist();
        if (_blacklist[to] > 0) revert ReceiverOnBlacklist();
        super._beforeTokenTransfer(from, to, amount);
    }

    //
    // Readers
    //

    /**
        Check that address is on blacklist
        @param user address to check
        @return bool true if blacklisted
     */
    function isBlacklisted(address user) external view returns (bool) {
        return _blacklist[user] > 0;
    }

    /**
        Read when user gets on blacklist
        @param user address to check
        @return timestamp of adding to blacklist (0=not on blacklist)
     */
    function getBlacklistTimestamp(address user)
        external
        view
        returns (uint256)
    {
        return _blacklist[user];
    }

    /**
        Total maximum supply that can be minted
        @return number of tokens
     */
    function getMaxSupply() external view returns (uint256) {
        return _maxSupply;
    }

    /**
        How many different signatures are need after request creation
        @return number of signatures need
     */
    function getSignaturesNeed() external view returns (uint256) {
        return _signaturesNeeded;
    }

    /**
        Get mint request information, revert on wrong index
        @param idx mint request index
        @return user address of mint target
        @return amount of tokens to be minted (0=already minted)
        @return signed number of signatures done
     */
    function getMintRequest(uint256 idx)
        external
        view
        returns (
            address user,
            uint256 amount,
            uint256 signed
        )
    {
        if (idx > _mints) revert WrongMintIndex();
        amount = _requests[idx].amount;
        user = _requests[idx].user;
        signed = _requests[idx].count;
    }

    /**
        How many mint requests are recorded in contract
        @return number of requests
     */
    function getMintsCount() external view returns (uint256) {
        return _mints;
    }

    /**
        Return signature status for user/request
        @param signer address of signer to check
        @param index request index
        @return boolean true if request signed by given signer
     */
    function getSignatureStatus(address signer, uint256 index)
        external
        view
        returns (bool)
    {
        return _requests[index].signed[signer];
    }
}
