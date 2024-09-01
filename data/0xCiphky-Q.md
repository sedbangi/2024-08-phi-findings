| Issue Number | Issue Title |
|---------------|-------------|
| [L-1] | Artists Royalties Fees sent to Protocol Instead of Artists |
| [L-2] | Lack of Upper Bound on Royalties Allows Excessive Fees |
| [L-3] | Cooldown Exploit Allows Blocking of Share Sales |
| [L-4] | merkleClaim allows claiming of any token in a credential |
##

## [L-1] Artists Royalties Fees sent to Protocol Instead of Artists

## **Relevant GitHub Links:**

https://github.com/code-423n4/2024-08-phi/blob/8c0985f7a10b231f916a51af5d506dd6b0c54120/src/PhiFactory.sol#L196

https://github.com/code-423n4/2024-08-phi/blob/8c0985f7a10b231f916a51af5d506dd6b0c54120/src/art/PhiNFT1155.sol#L195

https://github.com/code-423n4/2024-08-phi/blob/8c0985f7a10b231f916a51af5d506dd6b0c54120/src/PhiFactory.sol#L215

## **Vulnerability Details:**

The [`createArt`](https://github.com/code-423n4/2024-08-phi/blob/8c0985f7a10b231f916a51af5d506dd6b0c54120/src/PhiFactory.sol#L196) function allows users to create art that can be minted and sold on marketplaces. The `PhiNFT1155` contract supports the EIP2981 (NFT Royalty Standard), and artists can set royalty fees and recipients through the [`updateRoyalties`](https://github.com/code-423n4/2024-08-phi/blob/8c0985f7a10b231f916a51af5d506dd6b0c54120/src/art/PhiNFT1155.sol#L195) function in the `PhiNFT1155` contract or the [`updateArtSettings`](https://github.com/code-423n4/2024-08-phi/blob/8c0985f7a10b231f916a51af5d506dd6b0c54120/src/PhiFactory.sol#L215) function in the `PhiFactory` contract.

```solidity
    function _updateRoyalties(uint256 tokenId, RoyaltyConfiguration memory configuration) internal {
        if (configuration.royaltyRecipient == address(0) && configuration.royaltyBPS > 0) {
            revert InvalidRoyaltyRecipient();
        }

        royalties[tokenId] = configuration;

        emit UpdatedRoyalties(tokenId, msg.sender, configuration);
    }
```

The issue is that the `createArt` function does not allow artists to set an initial royalty fee. Until the artist manually sets the royalty settings, the default configuration applies: royalties are directed to the protocol fee destination at a 5% rate. This means that artists do not receive any royalties until they manually update the settings, with all initial royalties being sent to the protocol by default.

```solidity
    function getRoyalties(uint256 tokenId) public view returns (RoyaltyConfiguration memory) {
        if (!initilaized) revert NotInitialized();
        RoyaltyConfiguration memory config = royalties[tokenId];
        if (config.royaltyRecipient != address(0)) {
            return config;
        }
        // Return default configuration
        return RoyaltyConfiguration({ royaltyBPS: 500, royaltyRecipient: royaltyRecipient });
    }
```

## **Impact:**

Artists may unintentionally lose out on their earnings because the `createArt` function doesn’t let artists set the royalty configuration and the default setting directs royalties to the protocol until the artist takes action to update it.

## **Tools Used:**

- Manual analysis

## **Recommendation:**

Allow artists to set initial royalty fees and recipients during the `createArt` function call. This would ensure that artists receive their royalties immediately upon creation without needing to manually adjust settings afterward.

##

## [L-2] Lack of Upper Bound on Royalties Allows Excessive Fees

## **Relevant GitHub Links:**

https://github.com/code-423n4/2024-08-phi/blob/8c0985f7a10b231f916a51af5d506dd6b0c54120/src/PhiFactory.sol#L196

https://github.com/code-423n4/2024-08-phi/blob/8c0985f7a10b231f916a51af5d506dd6b0c54120/src/art/PhiNFT1155.sol#L195

https://github.com/code-423n4/2024-08-phi/blob/8c0985f7a10b231f916a51af5d506dd6b0c54120/src/PhiFactory.sol#L215

## **Vulnerability Details:**

The `PhiNFT1155` contract supports EIP2981 (NFT Royalty Standard), allowing artists to set royalty fees and recipients through the `updateRoyalties` function in the `PhiNFT1155` contract or the `updateArtSettings` function in the `PhiFactory` contract.

```solidity
    function _updateRoyalties(uint256 tokenId, RoyaltyConfiguration memory configuration) internal {
        if (configuration.royaltyRecipient == address(0) && configuration.royaltyBPS > 0) {
            revert InvalidRoyaltyRecipient();
        }

        royalties[tokenId] = configuration;

        emit UpdatedRoyalties(tokenId, msg.sender, configuration);
    }
```

While these functions allow artists to set their desired royalty rates, there is no upper bound or limit on the percentage (basis points) that can be set. This allows artists to initially set a low royalty fee to attract buyers, and then increase the fee substantially later, forcing existing holders to sell at much higher rates than they originally anticipated. 

The lack of an upper limit is inconsistent with the protocol’s approach elsewhere, such as with the `updateCred` function, which includes upper bounds on buyShareRoyalty and sellShareRoyalty to ensure that fees remain within reasonable levels. A similar upper bound should be implemented for art royalties.

## **Impact:**

Without an upper limit, artists can set excessively high royalties. Artists can also increase the royalty fee after users have minted, leaving those who decided to mint considering the lower fee no choice but to pay the higher fee when selling.

## **Tools Used:**

- Manual analysis

## **Recommendation:**

Implement an upper bound on the royalty percentage (e.g., a maximum of 5,000 basis points or 50%) similar to the constraints applied to buyShareRoyalty and sellShareRoyalty in the updateCred function.

##

## [L-3] Cooldown Exploit Allows Blocking of Share Sales

## **Relevant GitHub Links:**

https://github.com/code-423n4/2024-08-phi/blob/8c0985f7a10b231f916a51af5d506dd6b0c54120/src/Cred.sol#L186

https://github.com/code-423n4/2024-08-phi/blob/8c0985f7a10b231f916a51af5d506dd6b0c54120/src/Cred.sol#L588

## **Vulnerability Details:**

The [`buyShareCredFor`](https://github.com/code-423n4/2024-08-phi/blob/8c0985f7a10b231f916a51af5d506dd6b0c54120/src/Cred.sol#L186) function in the Cred contract allows users to buy shares on behalf of another account. During this process, the internal [`_handleTrade`](https://github.com/code-423n4/2024-08-phi/blob/8c0985f7a10b231f916a51af5d506dd6b0c54120/src/Cred.sol#L588) function is called, which resets the lastTradeTimestamp to the current block.timestamp after a buy and enforces a 10-minute cooldown period before the user can sell shares.

```solidity
    function _handleTrade(
        uint256 credId_,
        uint256 amount_,
        bool isBuy,
        address curator_,
        uint256 priceLimit
    )
        internal
        whenNotPaused
    {
        ...
        if (isBuy) {
            if (priceLimit != 0 && price + protocolFee + creatorFee > priceLimit) revert PriceExceedsLimit();
            if (supply + amount_ > MAX_SUPPLY) {
                revert MaxSupplyReached();
            }

            if (msg.value < price + protocolFee + creatorFee) {
                revert InsufficientPayment();
            }
        } else {
            if (priceLimit != 0 && price - protocolFee - creatorFee < priceLimit) revert PriceBelowLimit();
            if (block.timestamp <= lastTradeTimestamp[credId_][curator_] + SHARE_LOCK_PERIOD) {
                revert ShareLockPeriodNotPassed(
                    block.timestamp, lastTradeTimestamp[credId_][curator_] + SHARE_LOCK_PERIOD
                );
            }
            (, uint256 nums) = shareBalance[credId_].tryGet(curator_);
            if (nums < amount_) {
                revert InsufficientShares();
            }
        }

        _updateCuratorShareBalance(credId_, curator_, amount_, isBuy);

        if (isBuy) {
            cred.currentSupply += amount_;
            uint256 excessPayment = msg.value - price - protocolFee - creatorFee;
            if (excessPayment > 0) {
                _msgSender().safeTransferETH(excessPayment);
            }
            lastTradeTimestamp[credId_][curator_] = block.timestamp;
        } else {
            cred.currentSupply -= amount_;
            curator_.safeTransferETH(price - protocolFee - creatorFee);
        }
	...
    }
```

## **Impact:**

A user can exploit this functionality by buying a single share for another user, maliciously resetting their cooldown period. This effectively blocks the targeted user from selling their shares for the duration of the enforced cooldown, disrupting their trading ability.

## **Tools Used:**

- Manual analysis

## **Recommendation:**

While this should not pose a significant issue given the short 10-minute cooldown period, the protocol should be aware of the potential for exploitation.

##

## [L-4] merkleClaim allows claiming of any token in a credential

## **Relevant GitHub Links:**

https://github.com/code-423n4/2024-08-phi/blob/8c0985f7a10b231f916a51af5d506dd6b0c54120/src/PhiFactory.sol#L327

https://github.com/code-423n4/2024-08-phi/blob/8c0985f7a10b231f916a51af5d506dd6b0c54120/src/PhiFactory.sol#L352

## **Vulnerability Details:**

The PhiFactory contract provides two methods for claiming art: the [`signatureClaim`](https://github.com/code-423n4/2024-08-phi/blob/8c0985f7a10b231f916a51af5d506dd6b0c54120/src/PhiFactory.sol#L327) function, which uses a signature to claim a specific art reward, and the [`merkleClaim`](https://github.com/code-423n4/2024-08-phi/blob/8c0985f7a10b231f916a51af5d506dd6b0c54120/src/PhiFactory.sol#L352) function, which uses a Merkle proof for verification.

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

The `signatureClaim` function ensures the validity of the claim by including the specific artId_ (token) in the signed data, thereby restricting the claim to a specific token.

However, the `merkleClaim` function lacks similar specificity. It only verifies that the caller's address is authorized for the credential without checking for the specific artId_. This allows users to mint any token associated with that credential.

## **Impact:**

This allows users to mint any token under a credential, potentially leading to the unauthorized distribution of NFTs.

## **Tools Used:**

- Manual analysis

## **Recommendation:**

If there are different requirements or restrictions on specific NFTs within a credential, ensure that these are validated during the claim process.

