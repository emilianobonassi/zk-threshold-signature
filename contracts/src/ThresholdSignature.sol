// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {VerifySignatureVerifier} from "./VerifySignatureVerifier.sol";

library ECUtils {
    // secp256k1 scalar order of G.
    uint256 constant n =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    // Base point (generator) G
    uint256 constant Gx =
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 constant Gy =
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

    function calculateUScalar(uint256 rInv, uint256 msgHash)
        internal
        pure
        returns (uint256)
    {
        uint256 rInvNeg = n - rInv;
        return mulmod(rInvNeg, uint256(msgHash), n);
    }

    // s*G === Q
    // https://ethresear.ch/t/you-can-kinda-abuse-ecrecover-to-do-ecmul-in-secp256k1-today/2384/4
    function validateECMult(
        uint256 scalar,
        uint256 gx,
        uint256 gy,
        uint256 qx,
        uint256 qy
    ) internal pure returns (bool) {
        address signer = ecrecover(
            0,
            gy % 2 != 0 ? 28 : 27,
            bytes32(gx),
            bytes32(mulmod(scalar, gx, n))
        );

        address qAddress = address(
            uint160(uint256(keccak256(abi.encodePacked(qx, qy))))
        );
        return qAddress == signer;
    }

    function toRegister(uint256 a)
        internal
        pure
        returns (uint256[4] memory register)
    {
        register[3] = (a >> 192) & 0xFFFFFFFFFFFFFFFF;
        register[2] = (a >> 128) & 0xFFFFFFFFFFFFFFFF;
        register[1] = (a >> 64) & 0xFFFFFFFFFFFFFFFF;
        register[0] = a & 0xFFFFFFFFFFFFFFFF;
    }
}

struct SignatureProof {
    // Proof.
    uint256[2] a;
    uint256[2][2] b;
    uint256[2] c;
    // s*T + U = Q_a
    // T = r^{-1} * R
    // U = -(r^{-1})*m * G
    uint256 rInv;
    uint256[2] R;
    uint256[2] T;
    uint256[2] U;
    uint256 sTHash;
    uint256 nullifier;
}

error DuplicateSigner();
error InvalidSignature();
error RequiredSignersNotSatisfied();

library ThresholdSignature {
    function verifyProof(SignatureProof memory proof, bytes32 signedHash, bytes32 root)
        public
        view
        returns (bool)
    {
        uint256[11] memory input;
        uint256 u = ECUtils.calculateUScalar(proof.rInv, uint256(signedHash));

        // Assert that U = -r^{-1} * m * G
        if (
            !ECUtils.validateECMult(
                u,
                ECUtils.Gx,
                ECUtils.Gy,
                proof.U[0],
                proof.U[1]
            )
        ) {
            revert InvalidSignature();
        }

        // Assert that T = r^{-1} * R
        if (
            !ECUtils.validateECMult(
                proof.rInv,
                proof.R[0],
                proof.R[1],
                proof.T[0],
                proof.T[1]
            )
        ) {
            revert InvalidSignature();
        }

        input[0] = proof.sTHash;
        input[1] = proof.nullifier;
        input[2] = uint256(root);

        uint256[4] memory ux = ECUtils.toRegister(proof.U[0]);
        uint256[4] memory uy = ECUtils.toRegister(proof.U[1]);
        for (uint256 i = 0; i < 4; ++i) {
            input[3 + i] = ux[i];
            input[3 + 4 + i] = uy[i];
        }

        // TODO: Requires additional verification.

        return
            VerifySignatureVerifier.verifyProof(
                proof.a,
                proof.b,
                proof.c,
                input
            );
    }

    function validateSignature(
        bytes32 signedHash,
        bytes calldata signature,
        uint256 threshold,
        bytes32 _root
    ) internal view {
        SignatureProof[] memory proofs = abi.decode(signature, (SignatureProof[]));
        uint256 proofsLength = proofs.length;

        if (proofsLength < threshold) {
            revert RequiredSignersNotSatisfied();
        }

        for (uint256 i; i < proofsLength; ++i) {
            uint256 j = i + 1;
            SignatureProof memory proof = proofs[i];
            if (!verifyProof(proof, signedHash, _root)) {
                revert InvalidSignature();
            }

            for (j; j < proofsLength; ++j) {
                SignatureProof memory nextProof = proofs[j];
                if (proof.nullifier == nextProof.nullifier) {
                    revert DuplicateSigner();
                }
            }
        }
    }
}