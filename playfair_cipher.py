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

# -------------------- PLAYFAIR CIPHER --------------------

def generate_vigenere_key(uid):
    groups = [uid[i:i + 2] for i in range(0, len(uid), 2)]
    return "".join(chr((int(group) % 26) + ord("A")) for group in groups[:5])


def generate_key(uid):
    keyword = generate_vigenere_key(uid)
    result = []
    seen = set()
    for char in keyword.upper():
        char = "I" if char == "J" else char
        if char not in seen:
            seen.add(char)
            result.append(char)
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # J is combined with I
    for char in alphabet:
        if char not in seen:
            seen.add(char)
            result.append(char)
    return [result[i:i + 5] for i in range(0, 25, 5)]


def find_position(matrix, char):
    char = "I" if char == "J" else char
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == char:
                return row, col
    raise ValueError(f"Character {char!r} is not present in the Playfair matrix.")


def prepare_text(text):
    text = "".join(char for char in text.upper() if char.isalpha()).replace("J", "I")
    pairs = []
    index = 0
    while index < len(text):
        first = text[index]
        if index + 1 >= len(text):
            filler = "Q" if first == "X" else "X"
            pairs.append(first + filler)
            index += 1
        elif text[index] == text[index + 1]:
            filler = "Q" if first == "X" else "X"
            pairs.append(first + filler)
            index += 1
        else:
            pairs.append(text[index:index + 2])
            index += 2
    return pairs


def encrypt(text, matrix):
    result = []
    for pair in prepare_text(text):
        row1, col1 = find_position(matrix, pair[0])
        row2, col2 = find_position(matrix, pair[1])
        if row1 == row2:
            result.extend([matrix[row1][(col1 + 1) % 5], matrix[row2][(col2 + 1) % 5]])
        elif col1 == col2:
            result.extend([matrix[(row1 + 1) % 5][col1], matrix[(row2 + 1) % 5][col2]])
        else:
            result.extend([matrix[row1][col2], matrix[row2][col1]])
    return "".join(result)


def decrypt(text, matrix):
    text = "".join(char for char in text.upper() if char.isalpha()).replace("J", "I")
    if len(text) % 2 != 0:
        raise ValueError("Playfair ciphertext must contain an even number of letters.")
    result = []
    for index in range(0, len(text), 2):
        row1, col1 = find_position(matrix, text[index])
        row2, col2 = find_position(matrix, text[index + 1])
        if row1 == row2:
            result.extend([matrix[row1][(col1 - 1) % 5], matrix[row2][(col2 - 1) % 5]])
        elif col1 == col2:
            result.extend([matrix[(row1 - 1) % 5][col1], matrix[(row2 - 1) % 5][col2]])
        else:
            result.extend([matrix[row1][col2], matrix[row2][col1]])
    return "".join(result)


def expected_decryption(plaintext):
    return "".join(prepare_text(plaintext))


def run_experiment():
    df = prepare_dataset()
    uid_modified = UID[:-1] + str((int(UID[-1]) + 1) % 10)
    matrix = generate_key(UID)
    alternate_matrix = generate_key(uid_modified)
    print(f"UID: {UID}\nPlayfair matrix:")
    for row in matrix:
        print(" ".join(row))
    print("Modified-UID Playfair matrix:")
    for row in alternate_matrix:
        print(" ".join(row))

    df["Playfair_Ciphertext"] = ""
    df["Playfair_Decryption_OK (Y/N)"] = ""
    df["Confusion_Rating (1-5)"] = np.nan
    df["Diffusion_Rating (1-5)"] = np.nan
    df["Avalanche_%"] = np.nan
    df["Frequency_Concealment (1-5)"] = np.nan
    df["Remarks"] = ""

    for index, row in df.iterrows():
        plaintext = row["Plaintext"]
        ciphertext = encrypt(plaintext, matrix)
        decrypted = decrypt(ciphertext, matrix)
        expected = expected_decryption(plaintext)
        success = decrypted == expected
        df.at[index, "Playfair_Ciphertext"] = ciphertext
        df.at[index, "Playfair_Decryption_OK (Y/N)"] = "Y" if success else "N"

        confusion_pct = changed_percentage(ciphertext, encrypt(plaintext, alternate_matrix))
        modified_plaintext = one_char_modified(plaintext)
        diffusion_pct = changed_percentage(ciphertext, encrypt(modified_plaintext, matrix))
        clean_plaintext = "".join(c for c in plaintext.upper() if c.isalpha())

        df.at[index, "Confusion_Rating (1-5)"] = pct_to_rating(confusion_pct)
        df.at[index, "Diffusion_Rating (1-5)"] = pct_to_rating(diffusion_pct)
        df.at[index, "Avalanche_%"] = round(diffusion_pct, 2)
        df.at[index, "Frequency_Concealment (1-5)"] = frequency_concealment_rating(clean_plaintext, ciphertext)
        df.at[index, "Remarks"] = "Decryption verified." if success else "Decryption failed."

    test_plaintext = "my name is atharva"
    test_ciphertext = encrypt(test_plaintext, matrix)
    test_decrypted = decrypt(test_ciphertext, matrix)
    assert test_decrypted == expected_decryption(test_plaintext)
    print(f"\nTest plaintext : {test_plaintext}")
    print(f"Ciphertext     : {test_ciphertext}")
    print(f"Decrypted text : {test_decrypted}")

    if not df.empty:
        longest_text = df.loc[df["Plaintext"].str.len().idxmax(), "Plaintext"]
        plot_frequency(longest_text, "Playfair: Plaintext Frequency")
        plot_frequency(encrypt(longest_text, matrix), "Playfair: Ciphertext Frequency")

    output_file = "playfair_cipher_assignment.csv"
    df.to_csv(output_file, index=False)
    print(f"\nSaved results to {output_file}")
    print(f"Playfair key space (approximate): 25! = {math.factorial(25):.3e}")
    print(df.head())


if __name__ == "__main__":
    run_experiment()
