(1) When setting protocolFeePercent, you should add reasonable permissions to avoid setting protocolFeePercent too high, which may cause users to actually receive less assets than expected.
code link: https://github.com/code-423n4/2024-08-phi/blob/main/src/Cred.sol#L147-L149

(2) The whenNotPaused decorator in the _createCredInternal function is redundant code because the whenNotPaused decorator is already used in the createCred function declaration outside of it.
code link: https://github.com/code-423n4/2024-08-phi/blob/main/src/Cred.sol#L554

(3) In the updateArtSettings function, when checking the parameters, endTime_ should be greater than startTime_, so the code in line 233 of the PhiFactory contract should be "<=" instead of "<".
code link: https://github.com/code-423n4/2024-08-phi/blob/main/src/PhiFactory.sol#L233