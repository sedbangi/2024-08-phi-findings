## QA REPORT

|      | Issue                                                                                                                                                                                                                 |
| ---- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [01] | Creation of a new art can be DOS'ed                                                                                                                                                                                   |
| [02] | ETH amount received by `PhiNFT1155` contract through its `PhiNFT1155.receive` function is locked in `PhiNFT1155` contract and lost                                                                                    |
| [03] | Allowing art's properties like `startTime`, `endTime`, and `soulBounded` to be updated through `PhiFactory.updateArtSettings` function can cause other users' art claiming and art transfer transactions to be DOS'ed |
| [04] | `PhiFactory.signatureClaim` function does not check whether corresponding art's `verificationType` is `SIGNATURE` or not                                                                                              |
| [05] | `IPhiNFT1155.InitializePhiNFT1155` event does not include `credChainId` though it should                                                                                                                              |
| [06] | Calling `PhiNFT1155.mint` function can overwrite previously stored `minterData` and `advancedTokenURI` for corresponding `tokenId_`-`to_` combination                                                                 |

## [01] Creation of a new art can be DOS'ed

### Description
The `PhiFactory._createNewNFTContract` function should deterministically deploy a new art contract by executing `erc1155ArtAddress.cloneDeterministic(keccak256(abi.encodePacked(block.chainid, newArtId, credId)))`. Since `block.chainid`, `newArtId`, and `credId` are all known when the `PhiFactory._createNewNFTContract` transaction is in the mempool, a malicious actor can frontrun such transaction by calling the `LibClone.cloneDeterministic` function with the `erc1155ArtAddress` as the `implementation` input and the Keccak-256 hash of the corresponding `block.chainid`-`newArtId`-`credId` combination as the `salt` input. After such frontrunning, the `PhiFactory._createNewNFTContract` transaction reverts, and the creation of the new art corresponding to the `block.chainid`-`newArtId`-`credId` combination is DOS'ed.

https://github.com/code-423n4/2024-08-phi/blob/3a817c9dedca53ea27ff3e7988f8389086935b8b/src/PhiFactory.sol#L620-L649
```solidity
    function _createNewNFTContract(
        PhiArt storage art,
        uint256 newArtId,
        ERC1155Data memory createData_,
        uint256 credId,
        uint256 credChainId,
        string memory verificationType
    )
        private
        returns (address)
    {
@>      address payable newArt =
            payable(erc1155ArtAddress.cloneDeterministic(keccak256(abi.encodePacked(block.chainid, newArtId, credId))));

        art.artAddress = newArt;

        IPhiNFT1155Ownable(newArt).initialize(credChainId, credId, verificationType, protocolFeeDestination);

        credNFTContracts[credChainId][credId] = address(newArt);

        (bool success_, bytes memory response) =
            newArt.call{ value: msg.value }(abi.encodeWithSignature("createArtFromFactory(uint256)", newArtId));

        if (!success_) revert CreateFailed();
        uint256 tokenId = abi.decode(response, (uint256));
        emit ArtContractCreated(createData_.artist, address(newArt), credId);
        emit NewArtCreated(createData_.artist, credId, credChainId, newArtId, createData_.uri, address(newArt), tokenId);

        return address(newArt);
    }
```

https://github.com/vectorized/solady/blob/c453b8c69d93686c2d502c9a841901fca55b9454/src/utils/LibClone.sol#L127-L133
```solidity
    /// @dev Deploys a deterministic clone of `implementation` with `salt`.
    function cloneDeterministic(address implementation, bytes32 salt)
        internal
        returns (address instance)
    {
        instance = cloneDeterministic(0, implementation, salt);
    }
```

### Recommended Mitigation
The `PhiFactory._createNewNFTContract` function can be updated to further encode `msg.sender` in addition to `block.chainid`, `newArtId`, and `credId` for computing the salt for deploying an art contract.

## [02] ETH amount received by `PhiNFT1155` contract through its `PhiNFT1155.receive` function is locked in `PhiNFT1155` contract and lost

### Description
ETH can be directly sent to the `PhiNFT1155` contract through its `PhiNFT1155.receive` function. However, none of the `PhiNFT1155` contract's functions can transfer such ETH amount received by the `PhiNFT1155` contract out from such contract. Thus, after the `PhiNFT1155` contract receives some ETH through its `PhiNFT1155.receive` function, such received ETH amount is locked in the `PhiNFT1155` contract and lost.

https://github.com/code-423n4/2024-08-phi/blob/3a817c9dedca53ea27ff3e7988f8389086935b8b/src/art/PhiNFT1155.sol#L359-L361
```solidity
    receive() external payable {
        // This function is intentionally left empty to allow the contract to receive ETH
    }
```

### Recommended Mitigation
If there is no need for the `PhiNFT1155` contract to directly receive ETH through its `PhiNFT1155.receive` function, the `PhiNFT1155.receive` function can be removed. Otherwise, the `PhiNFT1155` contract can be updated to add a function, which should only be callable by the protocol's trusted admin, for transferring a specified amount of ETH out from the `PhiNFT1155` contract.

## [03] Allowing art's properties like `startTime`, `endTime`, and `soulBounded` to be updated through `PhiFactory.updateArtSettings` function can cause other users' art claiming and art transfer transactions to be DOS'ed

### Description
The `PhiFactory.updateArtSettings` function can be called by the corresponding art's artist to update such art's properties, such as its `startTime`, `endTime`, and `soulBounded` but such function call can unexpectedly DOS other users' art claiming and art transfer transactions.

When the `PhiFactory.updateArtSettings` transaction, which updates the corresponding art's `startTime` or `endTime`, is intentionally or unintentionally executed before the transaction for claiming such art, such art claiming transaction can revert unexpectedly because the `PhiFactory._validateAndUpdateClaimState` function would revert when such art's new `startTime` is later than `block.timestamp` or such art's new `endTime` is earlier than `block.timestamp` even though such art could be claimed if its `startTime` and `endTime` could remain at their original values.

Similarly, when the `PhiFactory.updateArtSettings` transaction, which updates the corresponding art's `soulBounded` from false to true, is intentionally or unintentionally executed before the transaction for transferring such art, such art transfer transaction can revert unexpectedly since the `PhiNFT1155.safeTransferFrom` and `PhiNFT1155.safeBatchTransferFrom` functions would revert when such art's new `soulBounded` is true even though such art could be transferred if its `soulBounded` could stay false.

https://github.com/code-423n4/2024-08-phi/blob/3a817c9dedca53ea27ff3e7988f8389086935b8b/src/PhiFactory.sol#L215-L257
```solidity
    function updateArtSettings(
        uint256 artId_,
        string memory url_,
        address receiver_,
        uint256 maxSupply_,
        uint256 mintFee_,
        uint256 startTime_,
        uint256 endTime_,
        bool soulBounded_,
        IPhiNFT1155Ownable.RoyaltyConfiguration memory configuration
    )
        external
        onlyArtCreator(artId_)
    {
        if (receiver_ == address(0)) {
            revert InvalidAddressZero();
        }

        if (endTime_ < startTime_) {
            revert InvalidTimeRange();
        }
        if (endTime_ < block.timestamp) {
            revert EndTimeInPast();
        }

        PhiArt storage art = arts[artId_];

        if (art.numberMinted > maxSupply_) {
            revert ExceedMaxSupply();
        }

        art.receiver = receiver_;
        art.maxSupply = maxSupply_;
        art.mintFee = mintFee_;
@>      art.startTime = startTime_;
@>      art.endTime = endTime_;
@>      art.soulBounded = soulBounded_;
        art.uri = url_;

        uint256 tokenId = IPhiNFT1155Ownable(art.artAddress).getTokenIdFromFactoryArtId(artId_);
        IPhiNFT1155Ownable(art.artAddress).updateRoyalties(tokenId, configuration);
        emit ArtUpdated(artId_, url_, receiver_, maxSupply_, mintFee_, startTime_, endTime_, soulBounded_);
    }
```

https://github.com/code-423n4/2024-08-phi/blob/3a817c9dedca53ea27ff3e7988f8389086935b8b/src/PhiFactory.sol#L702-L721
```solidity
    function _validateAndUpdateClaimState(uint256 artId_, address minter_, uint256 quantity_) private {
        PhiArt storage art = arts[artId_];

        // Common validations
        if (tx.origin != _msgSender() && msg.sender != art.artAddress && msg.sender != address(this)) {
            revert TxOriginMismatch();
        }
        if (msg.value < getArtMintFee(artId_, quantity_)) revert InvalidMintFee();
@>      if (block.timestamp < art.startTime) revert ArtNotStarted();
@>      if (block.timestamp > art.endTime) revert ArtEnded();
        if (quantity_ == 0) revert InvalidQuantity();
        if (art.numberMinted + quantity_ > art.maxSupply) revert OverMaxAllowedToMint();

        // Common state updates
        if (!credMinted[art.credChainId][art.credId][minter_]) {
            credMinted[art.credChainId][art.credId][minter_] = true;
        }
        artMinted[artId_][minter_] = true;
        art.numberMinted += quantity_;
    }
```

https://github.com/code-423n4/2024-08-phi/blob/3a817c9dedca53ea27ff3e7988f8389086935b8b/src/art/PhiNFT1155.sol#L307-L324
```solidity
    function safeTransferFrom(
        address from_,
        address to_,
        uint256 id_,
        uint256 value_,
        bytes memory data_
    )
        public
        override
    {
@>      if (from_ != address(0) && soulBounded(id_)) revert TokenNotTransferable();
        address sender = _msgSender();
        if (from_ != sender && !isApprovedForAll(from_, sender)) {
            revert ERC1155MissingApprovalForAll(sender, from_);
        }

        _safeTransferFrom(from_, to_, id_, value_, data_);
    }
```

https://github.com/code-423n4/2024-08-phi/blob/3a817c9dedca53ea27ff3e7988f8389086935b8b/src/art/PhiNFT1155.sol#L332-L350
```solidity
    function safeBatchTransferFrom(
        address from_,
        address to_,
        uint256[] memory ids_,
        uint256[] memory values_,
        bytes memory data_
    )
        public
        override
    {
        for (uint256 i; i < ids_.length; i++) {
@>          if (from_ != address(0) && soulBounded(ids_[i])) revert TokenNotTransferable();
        }
        address sender = _msgSender();
        if (from_ != sender && !isApprovedForAll(from_, sender)) {
            revert ERC1155MissingApprovalForAll(sender, from_);
        }
        _safeBatchTransferFrom(from_, to_, ids_, values_, data_);
    }
```

### Recommended Mitigation
One way to mitigate this issue is to update the `PhiFactory.updateArtSettings` function so calling it cannot update some properties of the corresponding art, such as its `startTime`, `endTime`, and `soulBounded`.

## [04] `PhiFactory.signatureClaim` function does not check whether corresponding art's `verificationType` is `SIGNATURE` or not

### Description
The `PhiFactory.signatureClaim` function does not check whether the corresponding art's `verificationType` is `SIGNATURE` or not, which is unlike the `PhiFactory.merkleClaim` function that checks to ensure that its corresponding art's `verificationType` is `MERKLE`. If the `phiSignerAddress` misfunctions and signs a claim data that is not for the `SIGNATURE` `verificationType`, the signature associated with such claim data can be used to claim an art through calling the `PhiFactory.signatureClaim` function even though such signature should not be allowed to be used for claiming such art.

https://github.com/code-423n4/2024-08-phi/blob/3a817c9dedca53ea27ff3e7988f8389086935b8b/src/PhiFactory.sol#L327-L346
```solidity
    function signatureClaim(
        bytes calldata signature_,
        bytes calldata encodeData_,
        MintArgs calldata mintArgs_
    )
        external
        payable
        whenNotPaused
    {
        (uint256 expiresIn_, address minter_, address ref_, address verifier_, uint256 artId_,, bytes32 data_) =
            abi.decode(encodeData_, (uint256, address, address, address, uint256, uint256, bytes32));

        if (expiresIn_ <= block.timestamp) revert SignatureExpired();
        if (_recoverSigner(keccak256(encodeData_), signature_) != phiSignerAddress) revert AddressNotSigned();

        _validateAndUpdateClaimState(artId_, minter_, mintArgs_.quantity);
        _processClaim(artId_, minter_, ref_, verifier_, mintArgs_.quantity, data_, mintArgs_.imageURI, msg.value);

        emit ArtClaimedData(artId_, "SIGNATURE", minter_, ref_, verifier_, arts[artId_].artAddress, mintArgs_.quantity);
    }
```

https://github.com/code-423n4/2024-08-phi/blob/3a817c9dedca53ea27ff3e7988f8389086935b8b/src/PhiFactory.sol#L352-L383
```solidity
    function merkleClaim(
        bytes32[] calldata proof_,
        bytes calldata encodeData_,
        MintArgs calldata mintArgs_,
        bytes32 leafPart_
    )
        external
        payable
        whenNotPaused
    {
        (address minter_, address ref_, uint256 artId_) = abi.decode(encodeData_, (address, address, uint256));
        PhiArt storage art = arts[artId_];

        bytes32 credMerkleRootHash = credMerkleRoot[art.credChainId][art.credId];
@>      if (minter_ == address(0) || !art.verificationType.eq("MERKLE") || credMerkleRootHash == bytes32(0)) {
            revert InvalidMerkleProof();
        }
        if (
            !MerkleProofLib.verifyCalldata(
                proof_, credMerkleRootHash, keccak256(bytes.concat(keccak256(abi.encode(minter_, leafPart_))))
            )
        ) {
            revert InvalidMerkleProof();
        }

        _validateAndUpdateClaimState(artId_, minter_, mintArgs_.quantity);
        _processClaim(
            artId_, minter_, ref_, art.credCreator, mintArgs_.quantity, leafPart_, mintArgs_.imageURI, msg.value
        );

        emit ArtClaimedData(artId_, "MERKLE", minter_, ref_, art.credCreator, art.artAddress, mintArgs_.quantity);
    }
```

### Recommended Mitigation
The `PhiFactory.signatureClaim` function can be updated to check whether the corresponding art's `verificationType` is `SIGNATURE` or not and revert if such `verificationType` is not `SIGNATURE`.

## [05] `IPhiNFT1155.InitializePhiNFT1155` event does not include `credChainId` though it should

### Description
The `PhiNFT1155.initialize` function emits the `IPhiNFT1155.InitializePhiNFT1155` event, which only includes `credId` and `verificationType`. Yet, two arts can be associated with the same `credId` but different `credChainId`. Since the emitted `IPhiNFT1155.InitializePhiNFT1155` event does not include `credChainId`, the protocol's monitor system cannot know which `credChainId`-`credId` combination that the corresponding art is truly associated with. This can lead to misbehaviors if the protocol needs to operate in certain way based on the emitted `IPhiNFT1155.InitializePhiNFT1155` event.

https://github.com/code-423n4/2024-08-phi/blob/3a817c9dedca53ea27ff3e7988f8389086935b8b/src/art/PhiNFT1155.sol#L96-L125
```solidity
    function initialize(
        uint256 credChainId_,
        uint256 credId_,
        string memory verificationType_,
        address protocolFeeDestination_
    )
        external
        initializer
    {
        __Ownable_init(msg.sender);

        __Pausable_init();
        __ReentrancyGuard_init();
        initializeRoyalties(protocolFeeDestination_);

        tokenIdCounter = 1;

        credChainId = credChainId_;
        credId = credId_;

        name = string(
            abi.encodePacked("Phi Cred-", uint256(credId_).toString(), " on Chain-", uint256(credChainId_).toString())
        );
        symbol = string(abi.encodePacked("PHI-", uint256(credId_).toString(), "-", uint256(credChainId_).toString()));
        phiFactoryContract = IPhiFactory(payable(msg.sender));

        protocolFeeDestination = phiFactoryContract.protocolFeeDestination();
        verificationType = verificationType_;
@>      emit InitializePhiNFT1155(credId_, verificationType_);
    }
```

https://github.com/code-423n4/2024-08-phi/blob/3a817c9dedca53ea27ff3e7988f8389086935b8b/src/interfaces/IPhiNFT1155.sol#L34
```solidity
    event InitializePhiNFT1155(uint256 credId, string verificationType);
```

### Recommended Mitigation
The `IPhiNFT1155.InitializePhiNFT1155` event can be updated to also include `credChainId` in addition to `credId` and `verificationType`. Moreover, the `PhiNFT1155.initialize` function needs to be updated to emit its `credChainId_` input value for the `IPhiNFT1155.InitializePhiNFT1155` event's `credChainId` data.

## [06] Calling `PhiNFT1155.mint` function can overwrite previously stored `minterData` and `advancedTokenURI` for corresponding `tokenId_`-`to_` combination

### Description
The `PhiNFT1155.mint` function executes `minterData[tokenId_][to_] = data_` and `advancedTokenURI[tokenId_][to_] = imageURI_`. Yet, since the same token ID associated with the same art to be claimed can be minted to the same address for multiple times, such as for different quantities, the data and image URI corresponding to the mints for the same `tokenId_`-`to_` combination can become different. In this case, calling the `PhiNFT1155.mint` function for the same `tokenId_`-`to_` combination can overwrite the `minterData` and `advancedTokenURI` previously stored for such combination. If the protocol needs to retrieve such previously stored `minterData` and `advancedTokenURI` for the corresponding `tokenId_`-`to_` combination for certain functionalities, these data would no longer be available, and using the newly stored `minterData` and `advancedTokenURI`instead can break the intended functionalities.

https://github.com/code-423n4/2024-08-phi/blob/3a817c9dedca53ea27ff3e7988f8389086935b8b/src/art/PhiNFT1155.sol#L283-L299
```solidity
    function mint(
        address to_,
        uint256 tokenId_,
        uint256 quantity_,
        string calldata imageURI_,
        bytes32 data_
    )
        internal
    {
@>      minterData[tokenId_][to_] = data_;
@>      advancedTokenURI[tokenId_][to_] = imageURI_;
        if (!minted[to_]) {
            minted[to_] = true;
        }

        _mint(to_, tokenId_, quantity_, "0x00");
    }
```

### Recommended Mitigation
One way to mitigate this issue is to update the `PhiNFT1155.mint` function to emit an event with the previously stored `minterData` and `advancedTokenURI` for the corresponding `tokenId_`-`to_` combination when these values differ from its `data_` and `imageURI_` input values. In this way, such previously stored `minterData` and `advancedTokenURI` can be retrieved.