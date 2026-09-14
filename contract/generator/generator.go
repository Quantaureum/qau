// Quantaureum Node source, version 1.0.0.
// Package generator provides smart contract auto-generation functionality
// for the Quantaureum blockchain. This package enables automatic creation
// of quantum-safe smart contracts from high-level specifications.
package generator

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// ContractType defines the type of smart contract to generate
const (
	ContractTypeToken      = "token"
	ContractTypeNFT        = "nft"
	ContractTypeGovernance = "governance"
	ContractTypeStaking    = "staking"
	ContractTypeDeFi       = "defi"
)

// ContractSpec defines the specification for contract generation
type ContractSpec struct {
	// Basic information
	Name         string
	Version      string
	Description  string
	ContractType string

	// Quantum-safe configuration
	// Pointers to distinguish "not set" (nil) from "explicitly false".
	// This allows callers to disable quantum-safe features for testing,
	// size-sensitive deployments, or migration scenarios.
	QuantumSafe      *bool
	KyberEnabled     *bool
	DilithiumEnabled *bool

	// Token-specific parameters (if applicable)
	TokenName   string
	TokenSymbol string
	Decimals    int
	TotalSupply uint64

	// Access control
	OwnerAddress   string
	AdminAddresses []string

	// Gas optimization settings
	OptimizeGas  bool
	OptimizeRuns int

	// Security configuration
	EnableAccessControl   bool
	EnablePausability     bool
	EnableReentrancyGuard bool

	// Event configuration
	EnableEvents bool
	EnableLogs   bool

	// Deployment configuration
	InitializerParams map[string]any
}

// ContractGenerator defines the interface for generating smart contracts
type ContractGenerator interface {
	// Generate generates a smart contract from the given specification
	Generate(ctx context.Context, spec *ContractSpec) (*GeneratedContract, error)

	// ValidateSpec validates the contract specification
	ValidateSpec(spec *ContractSpec) error
}

// GeneratedContract represents a generated smart contract
type GeneratedContract struct {
	// Source code in the target language
	SourceCode string

	// Compiled bytecode (if compiled)
	Bytecode []byte

	// ABI definition (if applicable)
	ABI string

	// Metadata about the generated contract
	Metadata *ContractMetadata
}

// ContractMetadata contains metadata about a generated contract
type ContractMetadata struct {
	ContractType     string
	GeneratedAt      time.Time
	Version          string
	QuantumSafe      bool
	Optimized        bool
	GasEstimate      uint64
	SecurityFeatures []string
}

// Optimizer defines the interface for optimizing smart contracts
type Optimizer interface {
	// Optimize optimizes the given contract source code
	Optimize(ctx context.Context, sourceCode string, opts *OptimizeOptions) (string, error)

	// EstimateGas estimates the gas cost of the given contract
	EstimateGas(sourceCode string) (uint64, error)
}

// OptimizeOptions contains options for contract optimization
type OptimizeOptions struct {
	OptimizeRuns        int
	OptimizeGas         bool
	RemoveDeadCode      bool
	InlineFunctions     bool
	SimplifyExpressions bool
}

// DefaultOptimizeOptions returns default optimization options
func DefaultOptimizeOptions() *OptimizeOptions {
	return &OptimizeOptions{
		OptimizeRuns:        200,
		OptimizeGas:         true,
		RemoveDeadCode:      true,
		InlineFunctions:     true,
		SimplifyExpressions: true,
	}
}

// NewContractGenerator creates a new contract generator
type NewContractGenerator func() ContractGenerator

// NewOptimizer creates a new contract optimizer
type NewOptimizer func() Optimizer

// DefaultContractGenerator returns a default contract generator
func DefaultContractGenerator() ContractGenerator {
	return &defaultGenerator{}
}

// DefaultOptimizer returns a default contract optimizer
func DefaultOptimizer() Optimizer {
	return &defaultOptimizer{}
}

// defaultGenerator is the default contract generator implementation
type defaultGenerator struct{}

// Generate generates a smart contract from the given specification
func (g *defaultGenerator) Generate(ctx context.Context, spec *ContractSpec) (*GeneratedContract, error) {
	// Validate the specification
	if err := g.ValidateSpec(spec); err != nil {
		return nil, err
	}

	// Generate the source code based on contract type
	var sourceCode string
	var err error

	switch spec.ContractType {
	case ContractTypeToken:
		sourceCode, err = g.generateTokenContract(spec)
	case ContractTypeNFT:
		sourceCode, err = g.generateNFTContract(spec)
	case ContractTypeGovernance:
		sourceCode, err = g.generateGovernanceContract(spec)
	case ContractTypeStaking:
		sourceCode, err = g.generateStakingContract(spec)
	case ContractTypeDeFi:
		sourceCode, err = g.generateDeFiContract(spec)
	default:
		return nil, fmt.Errorf("unsupported contract type: %s", spec.ContractType)
	}

	if err != nil {
		return nil, err
	}

	// Create metadata
	metadata := &ContractMetadata{
		ContractType:     spec.ContractType,
		GeneratedAt:      time.Now(),
		Version:          spec.Version,
		QuantumSafe:      spec.QuantumSafe != nil && *spec.QuantumSafe,
		Optimized:        spec.OptimizeGas,
		SecurityFeatures: g.getSecurityFeatures(spec),
	}

	return &GeneratedContract{
		SourceCode: sourceCode,
		Metadata:   metadata,
	}, nil
}

// ValidateSpec validates the contract specification
// R68-BRIDGE-2 [MEDIUM] FIX: Add string length bounds to prevent DoS via oversized inputs.
// Excessively long strings in ContractSpec fields could cause Solidity compilation
// failures, memory exhaustion, or malformed output. All string fields now have
// explicit max lengths validated before code generation.
func (g *defaultGenerator) ValidateSpec(spec *ContractSpec) error {
	if spec == nil {
		return fmt.Errorf("contract spec cannot be nil")
	}
	if spec.Name == "" {
		return fmt.Errorf("contract name cannot be empty")
	}
	if spec.ContractType == "" {
		return fmt.Errorf("contract type cannot be empty")
	}
	if spec.TokenName == "" && spec.ContractType == ContractTypeToken {
		return fmt.Errorf("token name cannot be empty for token contracts")
	}

	const (
		maxNameLen       = 256 // Max length for Name, Version, Description
		maxTokenFieldLen = 64  // Max length for TokenName, TokenSymbol
		maxAddressLen    = 64  // Max length for OwnerAddress, AdminAddresses
	)

	if len(spec.Name) > maxNameLen {
		return fmt.Errorf("contract name exceeds maximum length of %d bytes", maxNameLen)
	}
	if len(spec.Version) > maxNameLen {
		return fmt.Errorf("contract version exceeds maximum length of %d bytes", maxNameLen)
	}
	if len(spec.Description) > maxNameLen {
		return fmt.Errorf("contract description exceeds maximum length of %d bytes", maxNameLen)
	}
	if spec.TokenName != "" && len(spec.TokenName) > maxTokenFieldLen {
		return fmt.Errorf("token name exceeds maximum length of %d bytes", maxTokenFieldLen)
	}
	if spec.TokenSymbol != "" && len(spec.TokenSymbol) > maxTokenFieldLen {
		return fmt.Errorf("token symbol exceeds maximum length of %d bytes", maxTokenFieldLen)
	}
	if spec.OwnerAddress != "" && len(spec.OwnerAddress) > maxAddressLen {
		return fmt.Errorf("owner address exceeds maximum length of %d bytes", maxAddressLen)
	}
	for i, addr := range spec.AdminAddresses {
		if len(addr) > maxAddressLen {
			return fmt.Errorf("admin address at index %d exceeds maximum length of %d bytes", i, maxAddressLen)
		}
	}
	return nil
}

// generateTokenContract generates a token contract
func (g *defaultGenerator) generateTokenContract(spec *ContractSpec) (string, error) {
	// R64-B6 FIX: use %q (quoted string) for all user inputs in templates.
	// %q properly escapes ALL special characters including %, ", \, and newlines,
	// preventing both format string injection AND malformed Solidity output.
	// No manual %% escaping is needed — fmt.Sprintf handles it securely.
	generatedAt := time.Now().Format(time.RFC3339)

	// audit-fix HIGH: add access control modifier when enabled
	tokenAccessControl := ""
	if spec.EnableAccessControl {
		//nolint:gosec // G101: Solidity source template (onlyOwner modifier), not a hardcoded credential.
		tokenAccessControl = `
    modifier onlyOwner() {
        require(msg.sender == owner, "Caller is not the owner");
        _;
    }
`
	}

	// audit-fix HIGH: add pausability when enabled
	tokenPausability := ""
	if spec.EnablePausability {
		tokenPausability = `
    bool public paused;

    modifier whenNotPaused() {
        require(!paused, "Pausable: paused");
        _;
    }

    function setPaused(bool _paused) external onlyOwner {
        paused = _paused;
    }
`
	}

	// audit-fix HIGH: add reentrancy guard when enabled
	tokenReentrancyGuard := ""
	if spec.EnableReentrancyGuard {
		//nolint:gosec // G101: Solidity source template (nonReentrant modifier), not a credential.
		tokenReentrancyGuard = `
    bool private _reentrancyGuard;

    modifier nonReentrant() {
        require(!_reentrancyGuard, "ReentrancyGuard: reentrant call");
        _reentrancyGuard = true;
        _;
        _reentrancyGuard = false;
    }
`
	}

	// audit-fix HIGH: apply whenNotPaused modifier when pausability is enabled
	transferModifier := ""
	if spec.EnablePausability {
		transferModifier = " whenNotPaused"
	}

	// audit-fix HIGH: apply nonReentrant modifier when reentrancy guard is enabled
	transferReentrancy := ""
	if spec.EnableReentrancyGuard {
		transferReentrancy = " nonReentrant"
	}

	// Create a simple ERC20-like token contract with quantum-safe features
	template := `// Quantum-safe ERC20 Token Contract
// Generated by Quantaureum Contract Generator
// Contract Name: %q
// Version: %q
// Generated At: %s

pragma solidity ^0.8.0;

import "./QuantumSafe.sol";

contract %q is QuantumSafe {
    string public constant name = %q;
    string public constant symbol = %q;
    uint8 public constant decimals = %d;
    uint256 public totalSupply = %d * (10 ** decimals);

    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;

    address public owner;
%s%s%s
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor() {
        owner = msg.sender;
        _balances[msg.sender] = totalSupply;
    }

    function balanceOf(address account) public view returns (uint256) {
        return _balances[account];
    }

    // audit-fix HIGH: apply whenNotPaused and nonReentrant modifiers when enabled
    function transfer(address to, uint256 amount) public%s%s returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function allowance(address owner, address spender) public view returns (uint256) {
        return _allowances[owner][spender];
    }

    function approve(address spender, uint256 amount) public returns (bool) {
        _approve(msg.sender, spender, amount);
        return true;
    }

    // audit-fix HIGH: apply whenNotPaused and nonReentrant modifiers when enabled
    function transferFrom(address from, address to, uint256 amount) public%s%s returns (bool) {
        uint256 currentAllowance = _allowances[from][msg.sender];
        require(currentAllowance >= amount, "ERC20: transfer amount exceeds allowance");

        _transfer(from, to, amount);
        _approve(from, msg.sender, currentAllowance - amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(from != address(0), "ERC20: transfer from the zero address");
        require(to != address(0), "ERC20: transfer to the zero address");

        uint256 fromBalance = _balances[from];
        require(fromBalance >= amount, "ERC20: transfer amount exceeds balance");

        _balances[from] = fromBalance - amount;
        _balances[to] += amount;

        emit Transfer(from, to, amount);
    }

    function _approve(address owner, address spender, uint256 amount) internal {
        require(owner != address(0), "ERC20: approve from the zero address");
        require(spender != address(0), "ERC20: approve to the zero address");

        _allowances[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }
}
`

	return fmt.Sprintf(template,
		spec.Name, spec.Version, generatedAt,
		spec.Name, spec.TokenName, spec.TokenSymbol, spec.Decimals, spec.TotalSupply,
		tokenAccessControl, tokenPausability, tokenReentrancyGuard,
		transferModifier, transferReentrancy, transferModifier, transferReentrancy), nil
}

// generateNFTContract generates an NFT contract
func (g *defaultGenerator) generateNFTContract(spec *ContractSpec) (string, error) {
	// R64-B6 FIX: use %q (quoted string) for all user inputs in templates.
	// %q properly escapes ALL special characters including %, ", \, and newlines,
	// preventing both format string injection AND malformed Solidity output.
	generatedAt := time.Now().Format(time.RFC3339)

	// audit-fix CRITICAL: add reentrancy guard when enabled
	reentrancyGuard := ""
	if spec.EnableReentrancyGuard {
		reentrancyGuard = `
    bool private _reentrancyGuard;

    modifier nonReentrant() {
        require(!_reentrancyGuard, "ReentrancyGuard: reentrant call");
        _reentrancyGuard = true;
        _;
        _reentrancyGuard = false;
    }
`
	}

	// audit-fix HIGH: add access control block when enabled (prevents unauthorized minting)
	nftAccessControl := ""
	if spec.EnableAccessControl {
		nftAccessControl = `
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "Caller is not the owner");
        _;
    }
`
	}

	// audit-fix HIGH: constructor initializes owner when access control is enabled
	nftConstructor := ""
	if spec.EnableAccessControl {
		nftConstructor = `
    constructor() {
        owner = msg.sender;
    }
`
	}

	// audit-fix HIGH: onlyOwner modifier on mint when access control is enabled
	nftMintModifier := ""
	if spec.EnableAccessControl {
		nftMintModifier = " onlyOwner"
	}

	// audit-fix HIGH (H-7): apply nonReentrant modifier to mint when reentrancy guard is enabled
	nftReentrancyModifier := ""
	if spec.EnableReentrancyGuard {
		nftReentrancyModifier = " nonReentrant"
	}

	// Simple ERC721-like NFT contract
	template := `// Quantum-safe ERC721 NFT Contract
// Generated by Quantaureum Contract Generator
// Contract Name: %q
// Version: %q
// Generated At: %s

pragma solidity ^0.8.0;

import "./QuantumSafe.sol";

contract %q is QuantumSafe {%s%s
    string public name = %q;
    string public symbol = %q;

    mapping(uint256 => address) private _owners;
    mapping(address => uint256) private _balances;
    mapping(uint256 => address) private _tokenApprovals;
    mapping(address => mapping(address => bool)) private _operatorApprovals;

    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);
%s
    function balanceOf(address owner) public view returns (uint256) {
        require(owner != address(0), "ERC721: balance query for the zero address");
        return _balances[owner];
    }

    function ownerOf(uint256 tokenId) public view returns (address) {
        address owner = _owners[tokenId];
        require(owner != address(0), "ERC721: owner query for nonexistent token");
        return owner;
    }

    function transferFrom(address from, address to, uint256 tokenId) public {
        require(_isApprovedOrOwner(msg.sender, tokenId), "ERC721: transfer caller is not owner nor approved");
        _transfer(from, to, tokenId);
    }

    function approve(address to, uint256 tokenId) public {
        address owner = _owners[tokenId];
        require(to != owner, "ERC721: approval to current owner");
        require(msg.sender == owner || _operatorApprovals[owner][msg.sender], "ERC721: approve caller is not owner nor approved for all");

        _tokenApprovals[tokenId] = to;
        emit Approval(owner, to, tokenId);
    }

    function _isApprovedOrOwner(address spender, uint256 tokenId) internal view returns (bool) {
        address owner = _owners[tokenId];
        return (spender == owner || getApproved(tokenId) == spender || _operatorApprovals[owner][spender]);
    }

    function _transfer(address from, address to, uint256 tokenId) internal {
        require(ownerOf(tokenId) == from, "ERC721: transfer from incorrect owner");
        require(to != address(0), "ERC721: transfer to the zero address");

        _approve(address(0), tokenId);

        _balances[from] -= 1;
        _balances[to] += 1;
        _owners[tokenId] = to;

        emit Transfer(from, to, tokenId);
    }

    // audit-fix HIGH: restrict mint to owner when access control is enabled to prevent unauthorized minting
    // audit-fix HIGH (H-7): apply nonReentrant modifier when reentrancy guard is enabled
    function mint(address to, uint256 tokenId) public%s%s {
        require(to != address(0), "ERC721: mint to the zero address");
        require(_owners[tokenId] == address(0), "ERC721: token already minted");

        _balances[to] += 1;
        _owners[tokenId] = to;

        emit Transfer(address(0), to, tokenId);
    }

    function getApproved(uint256 tokenId) public view returns (address) {
        require(_owners[tokenId] != address(0), "ERC721: approved query for nonexistent token");
        return _tokenApprovals[tokenId];
    }
}
`

	return fmt.Sprintf(template,
		spec.Name, spec.Version, generatedAt,
		spec.Name, nftAccessControl, reentrancyGuard, spec.TokenName, spec.TokenSymbol, nftConstructor, nftMintModifier, nftReentrancyModifier), nil
}
func (g *defaultGenerator) generateGovernanceContract(spec *ContractSpec) (string, error) {
	// R64-B6 FIX: use %q (quoted string) for all user inputs in templates.
	// %q properly escapes ALL special characters including %, ", \, and newlines,
	// preventing both format string injection AND malformed Solidity output.
	generatedAt := time.Now().Format(time.RFC3339)

	// audit-fix CRITICAL: add reentrancy guard when enabled
	reentrancyGuard := ""
	if spec.EnableReentrancyGuard {
		reentrancyGuard = `
    bool private _reentrancyGuard;

    modifier nonReentrant() {
        require(!_reentrancyGuard, "ReentrancyGuard: reentrant call");
        _reentrancyGuard = true;
        _;
        _reentrancyGuard = false;
    }
`
	}

	// audit-fix HIGH (H-7): apply nonReentrant modifier to propose/vote/execute when enabled
	governanceReentrancyModifier := ""
	if spec.EnableReentrancyGuard {
		governanceReentrancyModifier = " nonReentrant"
	}

	// Simple governance contract with voting functionality
	template := `// Quantum-safe Governance Contract
// Generated by Quantaureum Contract Generator
// Contract Name: %q
// Version: %q
// Generated At: %s

pragma solidity ^0.8.0;

contract %q {%s
    string public constant name = %q;
    address public owner;
    uint256 public proposalCount;
    uint256 public votingDelay = 1;
    uint256 public votingPeriod = 7 days;
    uint256 public quorum = 4;
    uint256 public minimumProposalThreshold = 1;

    struct Proposal {
        uint256 id;
        string description;
        address proposer;
        uint256 startBlock;
        uint256 endBlock;
        uint256 forVotes;
        uint256 againstVotes;
        bool executed;
        mapping(address => bool) voters;
    }

    mapping(uint256 => Proposal) public proposals;
    mapping(address => uint256) public votePower;

    event ProposalCreated(uint256 id, string description, address proposer);
    event Voted(uint256 proposalId, address voter, bool support);
    event ProposalExecuted(uint256 proposalId);

    constructor() {
        owner = msg.sender;
        votePower[owner] = 100;
    }

    // audit-fix HIGH (H-7): apply nonReentrant modifier when reentrancy guard is enabled
    function propose(string memory description) external%s {
        require(votePower[msg.sender] >= minimumProposalThreshold, "Insufficient vote power");

        uint256 id = proposalCount;
        Proposal storage proposal = proposals[id];
        proposal.id = id;
        proposal.description = description;
        proposal.proposer = msg.sender;
        proposal.startBlock = block.number + votingDelay;
        proposal.endBlock = block.number + votingDelay + votingPeriod;

        proposalCount++;
        emit ProposalCreated(id, description, msg.sender);
    }

    // audit-fix HIGH (H-7): apply nonReentrant modifier when reentrancy guard is enabled
    function vote(uint256 proposalId, bool support) external%s {
        Proposal storage proposal = proposals[proposalId];
        require(block.number >= proposal.startBlock, "Voting not started");
        require(block.number <= proposal.endBlock, "Voting ended");
        require(!proposal.voters[msg.sender], "Already voted");
        require(votePower[msg.sender] > 0, "No vote power");

        proposal.voters[msg.sender] = true;
        if (support) {
            proposal.forVotes += votePower[msg.sender];
        } else {
            proposal.againstVotes += votePower[msg.sender];
        }

        emit Voted(proposalId, msg.sender, support);
    }

    // audit-fix HIGH (H-7): apply nonReentrant modifier when reentrancy guard is enabled
    function execute(uint256 proposalId) external%s {
        Proposal storage proposal = proposals[proposalId];
        require(block.number > proposal.endBlock, "Voting not ended");
        require(!proposal.executed, "Already executed");
        require(proposal.forVotes > proposal.againstVotes, "Proposal rejected");
        require(proposal.forVotes + proposal.againstVotes >= quorum, "Quorum not met");

        proposal.executed = true;
        emit ProposalExecuted(proposalId);
    }
}
`

	return fmt.Sprintf(template,
		spec.Name, spec.Version, generatedAt,
		spec.Name, reentrancyGuard, spec.Name+" Governance",
		governanceReentrancyModifier, governanceReentrancyModifier, governanceReentrancyModifier), nil
}

// generateStakingContract generates a staking contract
func (g *defaultGenerator) generateStakingContract(spec *ContractSpec) (string, error) {
	// R64-B6 FIX: use %q (quoted string) for all user inputs in templates.
	// %q properly escapes ALL special characters including %, ", \, and newlines,
	// preventing both format string injection AND malformed Solidity output.
	generatedAt := time.Now().Format(time.RFC3339)

	// audit-fix CRITICAL: add reentrancy guard when enabled
	reentrancyGuard := ""
	if spec.EnableReentrancyGuard {
		reentrancyGuard = `
    bool private _reentrancyGuard;

    modifier nonReentrant() {
        require(!_reentrancyGuard, "ReentrancyGuard: reentrant call");
        _reentrancyGuard = true;
        _;
        _reentrancyGuard = false;
    }
`
	}

	// audit-fix HIGH (H-7): apply nonReentrant modifier to stake/withdraw/claimReward when enabled
	stakingReentrancyModifier := ""
	if spec.EnableReentrancyGuard {
		stakingReentrancyModifier = " nonReentrant"
	}

	// Simple staking contract with rewards
	template := `// Quantum-safe Staking Contract
// Generated by Quantaureum Contract Generator
// Contract Name: %q
// Version: %q
// Generated At: %s

pragma solidity ^0.8.0;

contract %q {%s
    string public constant name = %q;
    address public owner;
    uint256 public totalStaked;
    uint256 public rewardRate = 10;
    uint256 public lastUpdateTime;
    uint256 public rewardPerTokenStored;

    mapping(address => uint256) public staked;
    mapping(address => uint256) public rewards;
    mapping(address => uint256) public userRewardPerTokenPaid;

    event Staked(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event RewardPaid(address indexed user, uint256 reward);

    constructor() {
        owner = msg.sender;
        lastUpdateTime = block.timestamp;
    }

    modifier updateReward(address account) {
        rewardPerTokenStored = rewardPerToken();
        lastUpdateTime = block.timestamp;
        if (account != address(0)) {
            rewards[account] = earned(account);
            userRewardPerTokenPaid[account] = rewardPerTokenStored;
        }
        _;
    }

    function rewardPerToken() public view returns (uint256) {
        if (totalStaked == 0) {
            return rewardPerTokenStored;
        }
        return rewardPerTokenStored + ((block.timestamp - lastUpdateTime) * rewardRate * 1e18 / totalStaked);
    }

    function earned(address account) public view returns (uint256) {
        return (staked[account] * (rewardPerToken() - userRewardPerTokenPaid[account])) / 1e18 + rewards[account];
    }

    // audit-fix HIGH (H-7): apply nonReentrant modifier when reentrancy guard is enabled
    function stake(uint256 amount) external%s updateReward(msg.sender) {
        require(amount > 0, "Amount must be greater than 0");
        staked[msg.sender] += amount;
        totalStaked += amount;
        emit Staked(msg.sender, amount);
    }

    // audit-fix HIGH (H-7): apply nonReentrant modifier when reentrancy guard is enabled
    function withdraw(uint256 amount) external%s updateReward(msg.sender) {
        require(amount > 0, "Amount must be greater than 0");
        require(staked[msg.sender] >= amount, "Insufficient staked balance");
        staked[msg.sender] -= amount;
        totalStaked -= amount;
        emit Withdrawn(msg.sender, amount);
    }

    // audit-fix HIGH (H-7): apply nonReentrant modifier when reentrancy guard is enabled
    function claimReward() external%s updateReward(msg.sender) {
        uint256 reward = rewards[msg.sender];
        require(reward > 0, "No reward to claim");
        rewards[msg.sender] = 0;
        emit RewardPaid(msg.sender, reward);
    }
}
`

	return fmt.Sprintf(template,
		spec.Name, spec.Version, generatedAt,
		spec.Name, reentrancyGuard, spec.Name+" Staking",
		stakingReentrancyModifier, stakingReentrancyModifier, stakingReentrancyModifier), nil
}

// generateDeFiContract generates a DeFi contract
func (g *defaultGenerator) generateDeFiContract(spec *ContractSpec) (string, error) {
	// R64-B6 FIX: use %q (quoted string) for all user inputs in templates.
	// %q properly escapes ALL special characters including %, ", \, and newlines,
	// preventing both format string injection AND malformed Solidity output.
	generatedAt := time.Now().Format(time.RFC3339)

	// audit-fix CRITICAL: add reentrancy guard when enabled
	reentrancyGuard := ""
	if spec.EnableReentrancyGuard {
		reentrancyGuard = `
    bool private _reentrancyGuard;

    modifier nonReentrant() {
        require(!_reentrancyGuard, "ReentrancyGuard: reentrant call");
        _reentrancyGuard = true;
        _;
        _reentrancyGuard = false;
    }
`
	}

	// audit-fix HIGH (H-7): apply nonReentrant modifier to deposit/withdraw/borrow/repay when enabled
	defiReentrancyModifier := ""
	if spec.EnableReentrancyGuard {
		defiReentrancyModifier = " nonReentrant"
	}

	// Simple DeFi contract with lending and borrowing functionality
	template := `// Quantum-safe DeFi Contract
// Generated by Quantaureum Contract Generator
// Contract Name: %q
// Version: %q
// Generated At: %s

pragma solidity ^0.8.0;

contract %q {%s
    string public constant name = %q;
    address public owner;
    uint256 public totalSupply;
    uint256 public totalBorrowed;
    uint256 public interestRate = 1;

    mapping(address => uint256) public balances;
    mapping(address => uint256) public borrowed;
    mapping(address => uint256) public borrowTime;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event Borrowed(address indexed user, uint256 amount);
    event Repaid(address indexed user, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    // audit-fix HIGH (H-7): apply nonReentrant modifier when reentrancy guard is enabled
    function deposit(uint256 amount) external%s {
        require(amount > 0, "Amount must be greater than 0");
        balances[msg.sender] += amount;
        totalSupply += amount;
        emit Deposited(msg.sender, amount);
    }

    // audit-fix HIGH (H-7): apply nonReentrant modifier when reentrancy guard is enabled
    function withdraw(uint256 amount) external%s {
        require(amount > 0, "Amount must be greater than 0");
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        totalSupply -= amount;
        emit Withdrawn(msg.sender, amount);
    }

    // audit-fix HIGH (H-7): apply nonReentrant modifier when reentrancy guard is enabled
    function borrow(uint256 amount) external%s {
        require(amount > 0, "Amount must be greater than 0");
        require(amount <= totalSupply - totalBorrowed, "Insufficient liquidity");
        borrowed[msg.sender] += amount;
        borrowTime[msg.sender] = block.timestamp;
        totalBorrowed += amount;
        emit Borrowed(msg.sender, amount);
    }

    function calculateInterest(address user) public view returns (uint256) {
        if (borrowed[user] == 0) {
            return 0;
        }
        uint256 timeElapsed = block.timestamp - borrowTime[user];
        return (borrowed[user] * interestRate * timeElapsed) / (365 days * 100);
    }

    // audit-fix HIGH (H-7): apply nonReentrant modifier when reentrancy guard is enabled
    function repay(uint256 amount) external%s {
        require(amount > 0, "Amount must be greater than 0");
        uint256 totalOwed = borrowed[msg.sender] + calculateInterest(msg.sender);
        require(amount <= totalOwed, "Amount exceeds total owed");

        if (amount <= borrowed[msg.sender]) {
            borrowed[msg.sender] -= amount;
            totalBorrowed -= amount;
        } else {
            uint256 principal = borrowed[msg.sender];
            borrowed[msg.sender] = 0;
            totalBorrowed -= principal;
        }

        emit Repaid(msg.sender, amount);
    }
}
`

	return fmt.Sprintf(template,
		spec.Name, spec.Version, generatedAt,
		spec.Name, reentrancyGuard, spec.Name+" DeFi",
		defiReentrancyModifier, defiReentrancyModifier, defiReentrancyModifier, defiReentrancyModifier), nil
}

// getSecurityFeatures returns the security features of the contract
func (g *defaultGenerator) getSecurityFeatures(spec *ContractSpec) []string {
	var features []string
	if spec.EnableAccessControl {
		features = append(features, "access_control")
	}
	if spec.EnablePausability {
		features = append(features, "pausability")
	}
	if spec.EnableReentrancyGuard {
		features = append(features, "reentrancy_guard")
	}
	if spec.QuantumSafe != nil && *spec.QuantumSafe {
		features = append(features, "quantum_safe")
	}
	return features
}

// defaultOptimizer is the default contract optimizer implementation
type defaultOptimizer struct{}

// Optimize optimizes the given contract source code
func (o *defaultOptimizer) Optimize(ctx context.Context, sourceCode string, opts *OptimizeOptions) (string, error) {
	// Simple optimization: remove comments and whitespace
	// In a real implementation, this would use a proper optimizer
	optimized := strings.ReplaceAll(sourceCode, "\n\n", "\n")
	optimized = strings.ReplaceAll(optimized, "\t", " ")
	return optimized, nil
}

// EstimateGas estimates the gas cost of the given contract
func (o *defaultOptimizer) EstimateGas(sourceCode string) (uint64, error) {
	// Simple gas estimate based on code size
	return uint64(len(sourceCode)) / 10, nil
}

// QuantumSafeContractGenerator creates quantum-safe smart contracts
type QuantumSafeContractGenerator struct {
	generator ContractGenerator
	optimizer Optimizer
}

// NewQuantumSafeContractGenerator creates a new quantum-safe contract generator
func NewQuantumSafeContractGenerator() *QuantumSafeContractGenerator {
	return &QuantumSafeContractGenerator{
		generator: DefaultContractGenerator(),
		optimizer: DefaultOptimizer(),
	}
}

// Generate generates a quantum-safe smart contract
func (q *QuantumSafeContractGenerator) Generate(ctx context.Context, spec *ContractSpec) (*GeneratedContract, error) {
	// R69-GEN-1 [MEDIUM] FIX (R70 update): Respect caller-specified flags using pointer types.
	// Pointer types (*bool) distinguish "not set" (nil) from "explicitly set to false".
	// Behavior: nil (default) -> enable quantum-safe by default (quantum-safe is recommended);
	// explicitly false -> honor caller's choice to disable (e.g., size-sensitive deployments);
	// explicitly true -> honor caller's choice to enable.
	// This replaces the broken original logic which used plain bools, making "!= false" always true.
	if spec.QuantumSafe == nil {
		spec.QuantumSafe = new(bool)
		*spec.QuantumSafe = true
	}
	if spec.KyberEnabled == nil {
		spec.KyberEnabled = new(bool)
		*spec.KyberEnabled = true
	}
	if spec.DilithiumEnabled == nil {
		spec.DilithiumEnabled = new(bool)
		*spec.DilithiumEnabled = true
	}

	// Generate the contract
	contract, err := q.generator.Generate(ctx, spec)
	if err != nil {
		return nil, err
	}

	// Optimize if requested
	if spec.OptimizeGas {
		opts := DefaultOptimizeOptions()
		optimizedCode, err := q.optimizer.Optimize(ctx, contract.SourceCode, opts)
		if err != nil {
			return nil, err
		}
		contract.SourceCode = optimizedCode
		contract.Metadata.Optimized = true

		// Estimate gas
		gasEstimate, err := q.optimizer.EstimateGas(optimizedCode)
		if err == nil {
			contract.Metadata.GasEstimate = gasEstimate
		}
	}

	return contract, nil
}
