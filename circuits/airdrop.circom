pragma circom 2.1.6;

// Dependencies: circomlib Poseidon, vocdoni keccak256, circom-ecdsa (secp256k1)
include "./vendor/circomlib/poseidon.circom";
include "./vendor/circomlib/comparators.circom";
include "./vendor/circomlib/keccak.circom";
include "./vendor/circom-ecdsa/ecdsa.circom";

// Airdrop membership + ownership circuit.
// Public inputs: root, nullifier, recipient.
// Witness: secp256k1 pubkey limbs, ECDSA signature limbs over fixed message, address bytes, merkle path.
template Airdrop(DEPTH, LIMB_BITS, LIMB_COUNT) {
    // Domain separator for this airdrop (scope nullifiers); replace with chainId/contract-specific value if needed.
    var DROP_DOMAIN = 1;

    // Public signals
    signal input root;
    signal input nullifier;
    signal input recipient;

    // Private inputs
    signal input addr_bytes[20];      // 20 byte Ethereum address (big-endian)
    signal input pk_x_limbs[LIMB_COUNT];
    signal input pk_y_limbs[LIMB_COUNT];
    signal input sig_r_limbs[LIMB_COUNT];
    signal input sig_s_limbs[LIMB_COUNT];
    signal input merkle_siblings[DEPTH];
    signal input merkle_pos[DEPTH];    // 0 = current is left, 1 = current is right

    // Fixed message hash limbs (keccak256("zk-airdrop-claim"), little-endian limbs of 64 bits)
    // Computed via ethers: keccak256(toUtf8Bytes("zk-airdrop-claim")) =
    // 0xb1383abb9dbacc33773143038d1f83cecf54eb16b340ec7025c1fb57d5f32191
    // Limbs (64-bit LE): [0x25c1fb57d5f32191, 0xcf54eb16b340ec70, 0x773143038d1f83ce, 0xb1383abb9dbacc33]
    assert(LIMB_COUNT == 4);
    var MSG_LIMBS[LIMB_COUNT];
    MSG_LIMBS[0] = 2720732004578697617;    // 0x25c1fb57d5f32191
    MSG_LIMBS[1] = 14939824346623962224;   // 0xcf54eb16b340ec70
    MSG_LIMBS[2] = 8588719646903862222;    // 0x773143038d1f83ce
    MSG_LIMBS[3] = 12770021320888601651;   // 0xb1383abb9dbacc33

    // Low-s bound (secp256k1 order / 2) limbs (little-endian 64-bit)
    var HALF_ORDER[LIMB_COUNT];
    HALF_ORDER[0] = 16134479119472337056; // 0xdfe92f46681b20a0
    HALF_ORDER[1] = 6725966010171805725;  // 0x5d576e7357a4501d
    HALF_ORDER[2] = 18446744073709551615; // 0xffffffffffffffff
    HALF_ORDER[3] = 9223372036854775807;  // 0x7fffffffffffffff

    // ECDSA verification
    component ecdsa = ECDSAVerifyNoPubkeyCheck(LIMB_BITS, LIMB_COUNT);
    for (var i = 0; i < LIMB_COUNT; i++) {
        ecdsa.r[i] <== sig_r_limbs[i];
        ecdsa.s[i] <== sig_s_limbs[i];
        ecdsa.msghash[i] <== MSG_LIMBS[i];
        ecdsa.pubkey[0][i] <== pk_x_limbs[i];
        ecdsa.pubkey[1][i] <== pk_y_limbs[i];
    }
    ecdsa.result === 1;

    // Enforce low-s (canonical signature): s < n/2
    component lt3 = LessThan(LIMB_BITS);
    component lt2 = LessThan(LIMB_BITS);
    component lt1 = LessThan(LIMB_BITS);
    component lt0 = LessThan(LIMB_BITS);
    component eq3 = IsEqual();
    component eq2 = IsEqual();
    component eq1 = IsEqual();
    lt3.in[0] <== sig_s_limbs[3]; lt3.in[1] <== HALF_ORDER[3];
    lt2.in[0] <== sig_s_limbs[2]; lt2.in[1] <== HALF_ORDER[2];
    lt1.in[0] <== sig_s_limbs[1]; lt1.in[1] <== HALF_ORDER[1];
    lt0.in[0] <== sig_s_limbs[0]; lt0.in[1] <== HALF_ORDER[0];
    eq3.in[0] <== sig_s_limbs[3]; eq3.in[1] <== HALF_ORDER[3];
    eq2.in[0] <== sig_s_limbs[2]; eq2.in[1] <== HALF_ORDER[2];
    eq1.in[0] <== sig_s_limbs[1]; eq1.in[1] <== HALF_ORDER[1];
    signal s1;
    signal s2;
    signal s3;
    // s1 = lt1 || (eq1 && lt0)
    s1 <== lt1.out + eq1.out * lt0.out;
    s1 * (s1 - 1) === 0;
    // s2 = lt2 || (eq2 && s1)
    s2 <== lt2.out + eq2.out * s1;
    s2 * (s2 - 1) === 0;
    // s3 = lt3 || (eq3 && s2)
    s3 <== lt3.out + eq3.out * s2;
    s3 * (s3 - 1) === 0;
    s3 === 1;

    // Pack limbs into field elements for hashing
    component pkxPack = Poseidon(LIMB_COUNT);
    component pkyPack = Poseidon(LIMB_COUNT);
    for (var i = 0; i < LIMB_COUNT; i++) {
        pkxPack.inputs[i] <== pk_x_limbs[i];
        pkyPack.inputs[i] <== pk_y_limbs[i];
    }

    // Build keccak input from pubkey (uncompressed 64 bytes: x||y, big-endian bytes)
    signal pk_bytes[64];
    component limb_x_bits[LIMB_COUNT];
    component limb_y_bits[LIMB_COUNT];
    component toByteX[LIMB_COUNT][8];
    component toByteY[LIMB_COUNT][8];
    for (var limb = 0; limb < LIMB_COUNT; limb++) {
        limb_x_bits[limb] = Num2Bits(LIMB_BITS);
        limb_x_bits[limb].in <== pk_x_limbs[limb];
        limb_y_bits[limb] = Num2Bits(LIMB_BITS);
        limb_y_bits[limb].in <== pk_y_limbs[limb];
        for (var b = 0; b < 8; b++) {
            var bitOffset = (7 - b) * 8;
            toByteX[limb][b] = Bits2Num(8);
            toByteY[limb][b] = Bits2Num(8);
            for (var k = 0; k < 8; k++) {
                toByteX[limb][b].in[k] <== limb_x_bits[limb].out[bitOffset + k];
                toByteY[limb][b].in[k] <== limb_y_bits[limb].out[bitOffset + k];
            }
            pk_bytes[limb * 8 + b] <== toByteX[limb][b].out;
            pk_bytes[32 + limb * 8 + b] <== toByteY[limb][b].out;
        }
    }

    // Keccak256(pubkey bytes)
    component keccak = Keccak(64 * 8, 256);
    component keccakByteBits[64];
    for (var i = 0; i < 64; i++) {
        keccakByteBits[i] = Num2Bits(8);
        keccakByteBits[i].in <== pk_bytes[i];
        for (var b = 0; b < 8; b++) {
            keccak.in[i * 8 + b] <== keccakByteBits[i].out[b];
        }
    }

    // Extract last 20 bytes of keccak hash
    signal derived_addr[20];
    component toAddrByte[20];
    for (var i = 0; i < 20; i++) {
        toAddrByte[i] = Bits2Num(8);
        for (var b = 0; b < 8; b++) {
            toAddrByte[i].in[b] <== keccak.out[(12 + i) * 8 + b];
        }
        derived_addr[i] <== toAddrByte[i].out;
        derived_addr[i] === addr_bytes[i];
    }

    // Poseidon(address) as leaf/nullifier (pad to field element with zeros in front handled by builder)
    // Pack 20 bytes into 32-byte big-endian: addr_field = sum(addr_bytes[i] * 256^(19-i))
    signal addr_partial[21];
    addr_partial[0] <== 0;
    for (var i = 0; i < 20; i++) {
        var exp = 19 - i;
        var factor = 1;
        for (var k = 0; k < exp; k++) {
            factor = factor * 256;
        }
        addr_partial[i + 1] <== addr_partial[i] + addr_bytes[i] * factor;
    }
    signal addr_field;
    addr_field <== addr_partial[20];

    component leafHasher = Poseidon(2);
    leafHasher.inputs[0] <== addr_field;
    leafHasher.inputs[1] <== 0; // zero sibling per builder
    signal leaf;
    leaf <== leafHasher.out;

    component sigHasher = Poseidon(2);
    component sigRPacker = Poseidon(LIMB_COUNT);
    component sigSPacker = Poseidon(LIMB_COUNT);
    for (var i = 0; i < LIMB_COUNT; i++) {
        sigRPacker.inputs[i] <== sig_r_limbs[i];
        sigSPacker.inputs[i] <== sig_s_limbs[i];
    }
    sigHasher.inputs[0] <== sigRPacker.out;
    sigHasher.inputs[1] <== sigSPacker.out;

    // Merkle path
    signal current[DEPTH + 1];
    current[0] <== leaf;
    component levelHashers[DEPTH];
    signal left[DEPTH];
    signal right[DEPTH];
    signal leftFromCurrent[DEPTH];
    signal leftFromSibling[DEPTH];
    signal rightFromCurrent[DEPTH];
    signal rightFromSibling[DEPTH];
    for (var i = 0; i < DEPTH; i++) {
        merkle_pos[i] * (merkle_pos[i] - 1) === 0;
        levelHashers[i] = Poseidon(2);
        leftFromCurrent[i] <== (1 - merkle_pos[i]) * current[i];
        leftFromSibling[i] <== merkle_pos[i] * merkle_siblings[i];
        left[i] <== leftFromCurrent[i] + leftFromSibling[i];

        rightFromCurrent[i] <== merkle_pos[i] * current[i];
        rightFromSibling[i] <== (1 - merkle_pos[i]) * merkle_siblings[i];
        right[i] <== rightFromCurrent[i] + rightFromSibling[i];

        levelHashers[i].inputs[0] <== left[i];
        levelHashers[i].inputs[1] <== right[i];
        current[i + 1] <== levelHashers[i].out;
    }
    current[DEPTH] === root;

    // Nullifier = Poseidon(Poseidon(sig_r, sig_s), DROP_DOMAIN)
    component nullifierHasher = Poseidon(2);
    nullifierHasher.inputs[0] <== sigHasher.out;
    nullifierHasher.inputs[1] <== DROP_DOMAIN;
    nullifier === nullifierHasher.out;
}

// Depth 26 (log2(leaf_count) for 2^26 leaves), limb bits 64, limb count 4.
component main = Airdrop(26, 64, 4);
