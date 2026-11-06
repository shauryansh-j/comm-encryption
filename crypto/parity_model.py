"""
SecureFlex Parity Predictor and Linear Invariant Software Model.
Reproduces the SecureFlex-ASCON hardware fault detection mechanism in software:
1. 5-bit S-box parity predictor (detects 320/320 single-bit output faults)
2. Linear-layer word-parity invariant (verifies 3-way rotation parity conservation)
"""
from typing import List, Tuple, Dict


def compute_word_parity(val: int) -> int:
    """Computes single-bit parity (0 or 1) of a 64-bit word."""
    return bin(val & 0xFFFFFFFFFFFFFFFF).count("1") % 2


# Ascon 5-bit S-box lookup table
ASCON_SBOX = [
    0x04, 0x0B, 0x0F, 0x07, 0x1E, 0x1D, 0x19, 0x1A,
    0x15, 0x16, 0x12, 0x11, 0x17, 0x14, 0x10, 0x13,
    0x02, 0x09, 0x0D, 0x05, 0x1C, 0x1B, 0x18, 0x1F,
    0x06, 0x0A, 0x0E, 0x01, 0x08, 0x0C, 0x00, 0x03,
]


def sbox_parity_lookup(in_5bit: int) -> int:
    """Returns the expected output parity of the Ascon S-box for a 5-bit input."""
    out_5bit = ASCON_SBOX[in_5bit & 0x1F]
    return bin(out_5bit).count("1") % 2


class SecureFlexPermutationModel:
    """
    Simulates the Ascon-p 320-bit permutation with integrated SecureFlex fault checkers:
    - S-Box output parity checks for each of the 64 bit-slices
    - Linear-layer word parity invariant checks across all 5 state words
    """

    ROTATIONS = [
        (19, 28),  # x0
        (61, 39),  # x1
        (1, 6),    # x2
        (10, 17),  # x3
        (7, 41),   # x4
    ]

    ROUND_CONSTANTS = [
        0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5,
        0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B
    ]

    def __init__(self, state: List[int] = None):
        self.state = list(state) if state is not None else [0] * 5

    @staticmethod
    def rotr64(val: int, r: int) -> int:
        val &= 0xFFFFFFFFFFFFFFFF
        return ((val >> r) | (val << (64 - r))) & 0xFFFFFFFFFFFFFFFF

    def step_round(self, round_idx: int, inject_sbox_fault: Dict[int, int] = None,
                   inject_linear_fault: Dict[int, int] = None) -> Dict[str, bool]:
        """
        Executes one permutation round and evaluates SecureFlex parity checks.
        Args:
            round_idx: Round constant index (0 to 11).
            inject_sbox_fault: Optional dict mapping slice index (0..63) to XOR mask.
            inject_linear_fault: Optional dict mapping word index (0..4) to XOR mask.
        Returns:
            Dict containing fault detection status:
            {'sbox_parity_match': bool, 'linear_invariant_match': bool, 'fault_detected': bool}
        """
        # 1. Constant Addition
        self.state[2] ^= self.ROUND_CONSTANTS[round_idx]

        # 2. Substitution Layer with S-box Parity Prediction
        sbox_parity_ok = True
        new_words = [0] * 5

        for col in range(64):
            # Extract 5-bit vertical slice: in_bits = x0[col], x1[col], x2[col], x3[col], x4[col]
            in_val = 0
            for w in range(5):
                bit = (self.state[w] >> col) & 1
                in_val |= (bit << (4 - w))

            # Predicted parity
            predicted_parity = sbox_parity_lookup(in_val)

            # Actual S-box output
            out_val = ASCON_SBOX[in_val]

            # Injected fault at S-box output slice
            if inject_sbox_fault and col in inject_sbox_fault:
                out_val ^= (inject_sbox_fault[col] & 0x1F)

            actual_parity = bin(out_val).count("1") % 2

            if actual_parity != predicted_parity:
                sbox_parity_ok = False

            # Reconstruct words from 5-bit slices
            for w in range(5):
                out_bit = (out_val >> (4 - w)) & 1
                new_words[w] |= (out_bit << col)

        self.state = new_words

        # 3. Linear Diffusion Layer with Invariant Verification
        # Invariant: Word parity before linear layer MUST equal word parity after linear layer!
        linear_invariant_ok = True
        pre_linear_parities = [compute_word_parity(w) for w in self.state]

        for i in range(5):
            r1, r2 = self.ROTATIONS[i]
            diffused = self.state[i] ^ self.rotr64(self.state[i], r1) ^ self.rotr64(self.state[i], r2)

            # Injected fault in linear layer output
            if inject_linear_fault and i in inject_linear_fault:
                diffused ^= inject_linear_fault[i]

            self.state[i] = diffused & 0xFFFFFFFFFFFFFFFF
            post_parity = compute_word_parity(self.state[i])

            if post_parity != pre_linear_parities[i]:
                linear_invariant_ok = False

        return {
            "sbox_parity_match": sbox_parity_ok,
            "linear_invariant_match": linear_invariant_ok,
            "fault_detected": not (sbox_parity_ok and linear_invariant_ok),
        }

