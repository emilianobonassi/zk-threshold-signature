import { secp256k1 } from '@noble/curves/secp256k1'
import * as mod from '@noble/curves/abstract/modular'
import * as utils from '@noble/curves/abstract/utils'
import { assert } from 'console'
import { groth16 } from 'snarkjs'
import * as ethers from 'ethers'

import { calculatePrecomputes, createTree, hasher, splitToRegisters, toBigInts } from './utils'

const generateNullifier = async (signer: ethers.Signer, secret: string) => {
    // generate signature for a secret
    const secretHash = ethers.hashMessage(secret)
    const signature = await signer.signMessage(secret)

    // extract pubkey
    const pubKey = ethers.SigningKey.recoverPublicKey(secretHash, signature)

    // create nullifier
    const publicKeyPoint = secp256k1.ProjectivePoint.fromHex(pubKey.slice(2))
    const Qa = [
        ...splitToRegisters(publicKeyPoint.toAffine().x),
        ...splitToRegisters(publicKeyPoint.toAffine().y),
    ]
    const nullifier = BigInt(await hasher([...Qa, BigInt(secretHash)]))
    
    return nullifier
}

const generateRoot = async (nullifiers: bigint[]) => {
    const tree = await createTree(4, 0n, 2);

    let response = {
        root: '',
        nullifiersInfo: []
    }

    for (const nullifier in nullifiers) {
        tree.insert(nullifier)
    }

    response.root = tree.root

    nullifiers.forEach((nullifier, i) => {
        const { pathIndices, siblings } = tree.createProof(i)
        response.nullifiersInfo.push({
            nullifier,
            pathIndices, 
            siblings
        })
    });

    return response
}

const createProof = async (signer: ethers.Signer, secret: string, msgToSign: string, pathIndices, siblings) => {
    const secretHash = ethers.hashMessage(secret)
    
    const msgToSignHash = ethers.hashMessage(msgToSign)
    const msgHash = utils.hexToBytes(msgToSignHash.slice(2))

    const signature = await signer.signMessage(msgToSign)
    const sig = ethers.Signature.from(signature)
    const pubKey = ethers.SigningKey.recoverPublicKey(msgToSignHash, signature)
    const publicKeyPoint = secp256k1.ProjectivePoint.fromHex(pubKey.slice(2))

    const r = BigInt(sig.r)
    const s = BigInt(sig.s)

    const m = mod.mod(utils.bytesToNumberBE(msgHash), secp256k1.CURVE.n)
    const sInv = mod.invert(s, secp256k1.CURVE.n) // s^-1
    const u1 = mod.mod(m * sInv, secp256k1.CURVE.n) // u1 = hs^-1 mod n
    const u2 = mod.mod(r * sInv, secp256k1.CURVE.n) // u2 = rs^-1 mod n

    const R = secp256k1.ProjectivePoint.BASE.multiplyAndAddUnsafe(
      publicKeyPoint,
      u1,
      u2,
    ) // R' = u1⋅G + u2⋅P

    // R'.x == R.x  <==> r' == r
    assert(R?.toAffine().x === r)

    // T = r^{-1} * R
    const rInv = mod.invert(r, secp256k1.CURVE.n)
    const T = R?.multiply(rInv)

    // U = (-r^{-1}) * m * G
    const u = mod.mod(
      mod.mod(-rInv, secp256k1.CURVE.n) * utils.bytesToNumberBE(msgHash),
      secp256k1.CURVE.n,
    )
    const U = secp256k1.ProjectivePoint.BASE.multiply(u)

    const sT = T?.multiply(s)
    const recoveredPublicKey = U.add(sT!).toAffine()

    // Recovered public key is not equal to public key point: x
    assert(recoveredPublicKey.x === publicKeyPoint.toAffine().x)
    // Recovered public key is not equal to public key point: y
    assert(recoveredPublicKey.y === publicKeyPoint.toAffine().y)

    const verified = secp256k1.verify({r, s}, msgHash, pubKey.slice(2))

    // Signature could not be verified
    assert(verified)

    const sRegisters = splitToRegisters(s)

    const URegisters = [
      splitToRegisters(U.toAffine().x),
      splitToRegisters(U.toAffine().y),
    ]
    const TPreComputes = calculatePrecomputes(T!)

    const inputs = {
      s: sRegisters,
      TPreComputes,
      U: URegisters,
      secret: BigInt(secretHash),//
      pathIndices,//
      siblings,//
    }

    const { proof, publicSignals } = await groth16.fullProve(
      inputs,
      'dist/verify_signature.wasm',
      'dist/verify_signature.zkey',
    )

    return {
        signatureProof: {
            a: toBigInts(proof.pi_a.slice(0, 2)) as [bigint, bigint],
            b: [
                toBigInts(proof.pi_b[0].reverse()),
                toBigInts(proof.pi_b[1].reverse()),
            ] as [[bigint, bigint], [bigint, bigint]],
            c: toBigInts(proof.pi_c.slice(0, 2)) as [bigint, bigint],
            rInv: rInv,
            R: [R?.toAffine().x!, R?.toAffine().y!],
            T: [T?.toAffine().x!, T?.toAffine().y!],
            U: [U?.toAffine().x!, U?.toAffine().y!],
            sTHash: BigInt(publicSignals[0]),
            nullifier: BigInt(publicSignals[1]),
        },
        proof,
        publicSignals
    }
}

describe.only('Misc Test', () => {

    it('should create set of signers and a sample signature', async () => {
        const numberOfSigners = 1;
        const signers = [...Array(numberOfSigners).keys()]
            .map((i) => new ethers.Wallet(`${i+1}`.repeat(64)))
        ;

        // TODO make api independent of signer but only of signatures/secret(hash)

        // everyone generate their own nullifier
        const secret = 'the secret word'
        const nullifiers = await Promise.all(
            signers.map(s => generateNullifier(s, secret))
        )

        // create the root aka the inclusion in the same group
        const root = await generateRoot(nullifiers)
        const getSignerNullifierinfo = (i) => root.nullifiersInfo.find(
            ({nullifier}) => nullifiers[i] === nullifier
        )

        // create proofs for a random message
        // signers needs to use secret used when created the nullifier and their position in the tree
        const msgToSign = 'oh yeah'
        const proofs = await Promise.all(
            signers.map((s, i) => {
                const {pathIndices, siblings} = getSignerNullifierinfo(i)
                return createProof(s, secret, msgToSign, pathIndices, siblings) 
            })
        )
    })
})