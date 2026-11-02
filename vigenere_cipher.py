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

# -------------------- VIGENERE CIPHER --------------------

def generate_key(uid):
    groups = [uid[i:i + 2] for i in range(0, len(uid), 2)]
    keyword = []
    for group in groups[:5]:
        value = int(group) % 26
        keyword.append(chr(value + ord("A")))
    if not keyword:
        raise ValueError("UID must contain at least one digit pair to generate a Vigenere key.")
    return "".join(keyword)


def encrypt(text, key):
    result = []
    key_index = 0
    for char in text.upper():
        if char.isalpha():
            plain_value = ord(char) - ord("A")
            key_value = ord(key[key_index % len(key)]) - ord("A")
            result.append(chr((plain_value + key_value) % 26 + ord("A")))
            key_index += 1
        else:
            result.append(char)
    return "".join(result)


def decrypt(text, key):
    result = []
    key_index = 0
    for char in text.upper():
        if char.isalpha():
            cipher_value = ord(char) - ord("A")
            key_value = ord(key[key_index % len(key)]) - ord("A")
            result.append(chr((cipher_value - key_value) % 26 + ord("A")))
            key_index += 1
        else:
            result.append(char)
    return "".join(result)


def run_experiment():
    df = prepare_dataset()
    uid_modified = UID[:-1] + str((int(UID[-1]) + 1) % 10)
    key = generate_key(UID)
    alternate_key = generate_key(uid_modified)
    print(f"UID: {UID}\nVigenere Key: {key}\nModified-UID Key: {alternate_key}")

    df["Vigenere_Ciphertext"] = ""
    df["Vigenere_Decryption_OK (Y/N)"] = ""
    df["Confusion_Rating (1-5)"] = np.nan
    df["Diffusion_Rating (1-5)"] = np.nan
    df["Avalanche_%"] = np.nan
    df["Frequency_Concealment (1-5)"] = np.nan
    df["Remarks"] = ""

    for index, row in df.iterrows():
        plaintext = row["Plaintext"]
        ciphertext = encrypt(plaintext, key)
        decrypted = decrypt(ciphertext, key)
        df.at[index, "Vigenere_Ciphertext"] = ciphertext
        df.at[index, "Vigenere_Decryption_OK (Y/N)"] = "Y" if decrypted == plaintext.upper() else "N"

        confusion_pct = changed_percentage(ciphertext, encrypt(plaintext, alternate_key))
        modified_plaintext = one_char_modified(plaintext)
        diffusion_pct = changed_percentage(ciphertext, encrypt(modified_plaintext, key))
        clean_plaintext = "".join(c for c in plaintext.upper() if c.isalpha())

        df.at[index, "Confusion_Rating (1-5)"] = pct_to_rating(confusion_pct)
        df.at[index, "Diffusion_Rating (1-5)"] = pct_to_rating(diffusion_pct)
        df.at[index, "Avalanche_%"] = round(diffusion_pct, 2)
        df.at[index, "Frequency_Concealment (1-5)"] = frequency_concealment_rating(clean_plaintext, ciphertext)
        df.at[index, "Remarks"] = "Decryption verified." if decrypted == plaintext.upper() else "Decryption failed."

    test_plaintext = "my name is atharva"
    test_ciphertext = encrypt(test_plaintext, key)
    test_decrypted = decrypt(test_ciphertext, key)
    assert test_decrypted == test_plaintext.upper()
    print(f"\nTest plaintext : {test_plaintext}")
    print(f"Ciphertext     : {test_ciphertext}")
    print(f"Decrypted text : {test_decrypted}")

    if not df.empty:
        longest_text = df.loc[df["Plaintext"].str.len().idxmax(), "Plaintext"]
        plot_frequency(longest_text, "Vigenere: Plaintext Frequency")
        plot_frequency(encrypt(longest_text, key), "Vigenere: Ciphertext Frequency")

    output_file = "vigenere_cipher_assignment.csv"
    df.to_csv(output_file, index=False)
    print(f"\nSaved results to {output_file}")
    print(f"Vigenere key space (5-letter key): 26^5 = {26 ** 5:,}")
    print(df.head())


if __name__ == "__main__":
    run_experiment()
