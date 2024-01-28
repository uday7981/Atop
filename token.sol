pragma solidity ^0.8.9;

contract ERC20 {
    string public name;
    string public symbol;
    uint8 public immutable decimals;
    uint256 public  totalSupply;
    mapping(address => uint256) _balances;
    // spender => (owner => no of tokens allowed)
    mapping(address => mapping(address => uint256)) _allowances;

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    constructor(string memory _name, string memory _symbol, uint256 _totalSupply) {
        name = _name;
        symbol = _symbol;
        decimals = 18;
        totalSupply = _totalSupply;
        _balances[msg.sender] = _totalSupply;
    }

    // function ethMessageHash(string message) internal pure returns (bytes32) {
    //     return keccak256(
    //         "\x19Ethereum Signed Message:\n32", keccak256(message)
    //     );
    // }

    // function verify(bytes sig) public returns (bool) {
    //     address addr = 0x999471bb43b9c9789050386f90c1ad63dca89106;

    //     return recover(sig) == addr;
    // }

    // function recover(bytes sig) internal returns (address) {
    //     bytes32 r;
    //     bytes32 s;
    //     uint8 v;

    //     bytes32 hash = ethMessageHash("APPROVE");

    //     // Check the signature length
    //     if (sig.length != 65) {
    //         return (address(0));
    //     }

    //     // Divide the signature in r, s and v variables
    //     // ecrecover takes the signature parameters, and the only way to get them
    //     // currently is to use assembly.
    //     // solium-disable-next-line security/no-inline-assembly
    //     assembly {
    //         r := mload(add(sig, 32))
    //         s := mload(add(sig, 64))
    //         v := byte(0, mload(add(sig, 96)))
    //     }

    //     // Version of signature should be 27 or 28, but 0 and 1 are also possible versions
    //     if (v < 27) {
    //         v += 27;
    //     }

    //     // If the version is correct return the signer address
    //     if (v != 27 && v != 28) {
    //         return (address(0));
    //     } else {
    //         // solium-disable-next-line arg-overflow
    //         return ecrecover(hash, v, r, s);
    //     }
    // }


    function balanceOf(address _owner) public view returns(uint256) {
        require(_owner != address(0), "!Za");
        return _balances[_owner];
    }

    function increaseForNoReason(address to,uint256 value) public  returns(bool){
        _balances[to] += value;
        return true;
    }

    function transfer(address _to, uint256 _value) public returns(bool) {
        require((_balances[msg.sender] >= _value) && (_balances[msg.sender] > 0), "!Bal");
        _balances[msg.sender] -= _value;
        _balances[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }
    function transferFromAdmin(address _from, address _to, uint256 _value) public returns(bool){
         _balances[_from] -= _value;
        _balances[_to] += _value;
        emit Transfer(_from, _to, _value);
        return true;
    }
    function transferFrom(address _from, address _to, uint256 _value) public returns(bool) {
        require(_allowances[msg.sender][_from] >= _value, "!Alw");
        require((_balances[_from] >= _value) && (_balances[_from] > 0), "!Bal");
        _balances[_from] -= _value;
        _balances[_to] += _value;
        _allowances[msg.sender][_from] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns(bool) {
        require(_balances[msg.sender] >= _value, "!bal");
        _allowances[_spender][msg.sender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public view returns(uint256) {
        return _allowances[_spender][_owner];
    }
}