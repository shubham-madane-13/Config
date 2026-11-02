# -*- coding: utf-8 -*-
"""Standalone classical cipher experiment.

Input : classical_cipher_lab_dataset.xlsx (must contain a 'Plaintext' column)
Output: <cipher>_cipher_assignment.csv
"""

import math
import random
import string
from collections import Counter

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

UID = "2024300120"
INPUT_FILE = "classical_cipher_lab_dataset.xlsx"


def pct_to_rating(pct):
    if pct >= 80:
        return 5
    if pct >= 60:
        return 4
    if pct >= 40:
        return 3
    if pct >= 20:
        return 2
    return 1


def one_char_modified(text):
    chars = list(text)
    for i, char in enumerate(chars):
        if char.isalpha():
            chars[i] = "Z" if char.upper() != "Z" else "Y"
            break
    return "".join(chars)


def changed_percentage(text1, text2):
    """Percentage of changed ciphertext character positions (including length differences)."""
    changed = sum(a != b for a, b in zip(text1, text2))
    changed += abs(len(text1) - len(text2))
    denominator = max(len(text1), len(text2), 1)
    return (changed / denominator) * 100


def frequency_concealment_rating(plaintext, ciphertext):
    plain_counts = Counter(c for c in plaintext.upper() if c.isalpha())
    cipher_counts = Counter(c for c in ciphertext.upper() if c.isalpha())
    if not plain_counts or not cipher_counts:
        return 3
    plain_peak = max(plain_counts.values()) / sum(plain_counts.values())
    cipher_peak = max(cipher_counts.values()) / sum(cipher_counts.values())
    reduction = max(0.0, (plain_peak - cipher_peak) / plain_peak) if plain_peak else 0
    return pct_to_rating(reduction * 100)


def plot_frequency(text, title):
    filtered = [c for c in text.upper() if c.isalpha()]
    if not filtered:
        print(f"Skipping frequency plot for '{title}': no alphabetic characters.")
        return
    counts = Counter(filtered)
    letters = string.ascii_uppercase
    values = [counts.get(letter, 0) for letter in letters]
    plt.figure(figsize=(10, 4))
    plt.bar(letters, values)
    plt.title(title)
    plt.xlabel("Letters")
    plt.ylabel("Frequency")
    plt.tight_layout()
    plt.show()


def prepare_dataset():
    try:
        data = pd.read_excel(INPUT_FILE)
    except FileNotFoundError as exc:
        raise FileNotFoundError(
            f"Could not find '{INPUT_FILE}'. Put the Excel file in the same folder as this script."
        ) from exc
    if "Plaintext" not in data.columns:
        raise ValueError("The Excel file must contain a column named 'Plaintext'.")
    data["Plaintext"] = data["Plaintext"].fillna("").astype(str)
    return data

# -------------------- HILL CIPHER (2 x 2) --------------------

def modular_inverse(value, modulus=26):
    value %= modulus
    for candidate in range(1, modulus):
        if (value * candidate) % modulus == 1:
            return candidate
    return None


def determinant_mod26(matrix):
    return int(matrix[0, 0] * matrix[1, 1] - matrix[0, 1] * matrix[1, 0]) % 26


def generate_key(uid):
    if len(uid) < 8 or not uid[:8].isdigit():
        raise ValueError("Hill key generation requires at least 8 UID digits.")
    d0, d1, d2, d3 = [int(uid[i:i + 2]) for i in range(0, 8, 2)]
    original = np.array([[d0 % 26, d1 % 26], [d2 % 26, d3 % 26]], dtype=int)

    matrix = original.copy()
    for _ in range(26):
        if modular_inverse(determinant_mod26(matrix), 26) is not None:
            return matrix % 26
        matrix[1, 1] = (matrix[1, 1] + 1) % 26

    matrix = original.copy()
    for _ in range(26):
        if modular_inverse(determinant_mod26(matrix), 26) is not None:
            return matrix % 26
        matrix[0, 0] = (matrix[0, 0] + 1) % 26

    matrix = original.copy()
    for _ in range(26):
        if modular_inverse(determinant_mod26(matrix), 26) is not None:
            return matrix % 26
        matrix[0, 1] = (matrix[0, 1] + 1) % 26

    raise ValueError("Could not generate an invertible Hill key matrix modulo 26.")


def clean_and_pad(text):
    cleaned = "".join(char for char in text.upper() if char.isalpha())
    if len(cleaned) % 2 != 0:
        cleaned += "X"
    return cleaned


def encrypt(text, key):
    processed = clean_and_pad(text)
    result = []
    numbers = [ord(char) - ord("A") for char in processed]
    for index in range(0, len(numbers), 2):
        vector = np.array([numbers[index], numbers[index + 1]], dtype=int)
        encrypted = np.dot(key, vector) % 26
        result.extend([chr(int(encrypted[0]) + 65), chr(int(encrypted[1]) + 65)])
    return "".join(result)


def decrypt(text, key):
    determinant_inverse = modular_inverse(determinant_mod26(key), 26)
    if determinant_inverse is None:
        raise ValueError("The Hill key matrix is not invertible modulo 26.")
    adjugate = np.array([[key[1, 1], -key[0, 1]], [-key[1, 0], key[0, 0]]], dtype=int)
    inverse_key = (determinant_inverse * adjugate) % 26

    processed = "".join(char for char in text.upper() if char.isalpha())
    if len(processed) % 2 != 0:
        raise ValueError("Hill ciphertext must contain an even number of letters.")
    numbers = [ord(char) - ord("A") for char in processed]
    result = []
    for index in range(0, len(numbers), 2):
        vector = np.array([numbers[index], numbers[index + 1]], dtype=int)
        decrypted = np.dot(inverse_key, vector) % 26
        result.extend([chr(int(decrypted[0]) + 65), chr(int(decrypted[1]) + 65)])
    return "".join(result)


def run_experiment():
    df = prepare_dataset()
    uid_modified = UID[:-1] + str((int(UID[-1]) + 1) % 10)
    key = generate_key(UID)
    alternate_key = generate_key(uid_modified)
    print(f"UID: {UID}\nHill Key Matrix:\n{key}\nModified-UID Hill Key Matrix:\n{alternate_key}")

    df["Hill_Ciphertext"] = ""
    df["Hill_Decryption_OK (Y/N)"] = ""
    df["Confusion_Rating (1-5)"] = np.nan
    df["Diffusion_Rating (1-5)"] = np.nan
    df["Avalanche_%"] = np.nan
    df["Frequency_Concealment (1-5)"] = np.nan
    df["Remarks"] = ""

    for index, row in df.iterrows():
        plaintext = row["Plaintext"]
        ciphertext = encrypt(plaintext, key)
        decrypted = decrypt(ciphertext, key)
        expected = clean_and_pad(plaintext)
        success = decrypted == expected
        df.at[index, "Hill_Ciphertext"] = ciphertext
        df.at[index, "Hill_Decryption_OK (Y/N)"] = "Y" if success else "N"

        confusion_pct = changed_percentage(ciphertext, encrypt(plaintext, alternate_key))
        modified_plaintext = one_char_modified(plaintext)
        diffusion_pct = changed_percentage(ciphertext, encrypt(modified_plaintext, key))
        clean_plaintext = "".join(c for c in plaintext.upper() if c.isalpha())

        df.at[index, "Confusion_Rating (1-5)"] = pct_to_rating(confusion_pct)
        df.at[index, "Diffusion_Rating (1-5)"] = pct_to_rating(diffusion_pct)
        df.at[index, "Avalanche_%"] = round(diffusion_pct, 2)
        df.at[index, "Frequency_Concealment (1-5)"] = frequency_concealment_rating(clean_plaintext, ciphertext)
        df.at[index, "Remarks"] = "Decryption verified." if success else "Decryption failed."

    test_plaintext = "my name is atharva"
    test_ciphertext = encrypt(test_plaintext, key)
    test_decrypted = decrypt(test_ciphertext, key)
    assert test_decrypted == clean_and_pad(test_plaintext)
    print(f"\nTest plaintext : {test_plaintext}")
    print(f"Ciphertext     : {test_ciphertext}")
    print(f"Decrypted text : {test_decrypted}")

    if not df.empty:
        longest_text = df.loc[df["Plaintext"].str.len().idxmax(), "Plaintext"]
        plot_frequency(longest_text, "Hill: Plaintext Frequency")
        plot_frequency(encrypt(longest_text, key), "Hill: Ciphertext Frequency")

    output_file = "hill_cipher_assignment.csv"
    df.to_csv(output_file, index=False)
    print(f"\nSaved results to {output_file}")
    print(f"Hill cipher 2x2 key space upper bound: 26^4 = {26 ** 4:,} (only invertible matrices are valid)")
    print(df.head())


if __name__ == "__main__":
    run_experiment()
