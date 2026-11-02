import random
import math
import string
from collections import Counter
import pandas as pd
import matplotlib.pyplot as plt
UID = '2024300020'
INPUT_CSV = 'classical_cipher_assignment_dataset.csv'
OUTPUT_CSV = 'classical_cipher_assignment_dataset_completed.csv'
ALPHA = string.ascii_uppercase
CIPHERS = ['Caesar', 'Mono', 'Vigenere', 'Playfair', 'Hill']

def clean(text: str) -> str:
    return ''.join((ch for ch in str(text).upper() if ch in ALPHA))

def caesar_key(uid: str) -> int:
    return sum((int(d) for d in uid)) % 25 + 1

def mono_key(uid: str) -> str:
    rng = random.Random(int(uid))
    letters = list(ALPHA)
    rng.shuffle(letters)
    return ''.join(letters)

def vigenere_key(uid: str) -> str:
    pairs = [int(uid[i:i + 2]) for i in range(0, 10, 2)]
    return ''.join((ALPHA[p % 26] for p in pairs))

def playfair_matrix(keyword: str):
    seen = []
    for ch in keyword.upper().replace('J', 'I') + ALPHA.replace('J', ''):
        if ch not in seen:
            seen.append(ch)
    return seen

def hill_key(uid: str):
    a, b, c, d = (int(uid[i:i + 2]) % 26 for i in (0, 2, 4, 6))
    for _ in range(26):
        for _ in range(26):
            det = (a * d - b * c) % 26
            if math.gcd(det, 26) == 1:
                return [[a, b], [c, d]]
            d = (d + 1) % 26
        a = (a + 1) % 26
    raise ValueError('No valid Hill key found')

def generate_keys(uid: str) -> dict:
    vk = vigenere_key(uid)
    return {'Caesar': caesar_key(uid), 'Mono': mono_key(uid), 'Vigenere': vk, 'Playfair': playfair_matrix(vk), 'Hill': hill_key(uid), 'PlayfairKeyword': vk}

def caesar_encrypt(pt: str, k: int) -> str:
    return ''.join((ALPHA[(ALPHA.index(ch) + k) % 26] for ch in pt))

def caesar_decrypt(ct: str, k: int) -> str:
    return ''.join((ALPHA[(ALPHA.index(ch) - k) % 26] for ch in ct))

def mono_encrypt(pt: str, key: str) -> str:
    table = {ALPHA[i]: key[i] for i in range(26)}
    return ''.join((table[ch] for ch in pt))

def mono_decrypt(ct: str, key: str) -> str:
    table = {key[i]: ALPHA[i] for i in range(26)}
    return ''.join((table[ch] for ch in ct))

def vigenere_encrypt(pt: str, key: str) -> str:
    return ''.join((ALPHA[(ALPHA.index(ch) + ALPHA.index(key[i % len(key)])) % 26] for i, ch in enumerate(pt)))

def vigenere_decrypt(ct: str, key: str) -> str:
    return ''.join((ALPHA[(ALPHA.index(ch) - ALPHA.index(key[i % len(key)])) % 26] for i, ch in enumerate(ct)))

def playfair_prepare(pt: str) -> str:
    pt = pt.replace('J', 'I')
    out = []
    i = 0
    while i < len(pt):
        a = pt[i]
        b = pt[i + 1] if i + 1 < len(pt) else None
        if b is None:
            out += [a, 'X']
            i += 1
        elif a == b:
            out += [a, 'X' if a != 'X' else 'Q']
            i += 1
        else:
            out += [a, b]
            i += 2
    return ''.join(out)

def playfair_crypt(text: str, matrix, decrypt: bool=False) -> str:
    shift = -1 if decrypt else 1
    pos = {ch: divmod(i, 5) for i, ch in enumerate(matrix)}
    out = []
    for i in range(0, len(text), 2):
        r1, c1 = pos[text[i]]
        r2, c2 = pos[text[i + 1]]
        if r1 == r2:
            out += [matrix[r1 * 5 + (c1 + shift) % 5], matrix[r2 * 5 + (c2 + shift) % 5]]
        elif c1 == c2:
            out += [matrix[(r1 + shift) % 5 * 5 + c1], matrix[(r2 + shift) % 5 * 5 + c2]]
        else:
            out += [matrix[r1 * 5 + c2], matrix[r2 * 5 + c1]]
    return ''.join(out)

def playfair_encrypt(pt: str, matrix) -> str:
    return playfair_crypt(playfair_prepare(pt), matrix)

def playfair_decrypt(ct: str, matrix) -> str:
    return playfair_crypt(ct, matrix, decrypt=True)

def hill_prepare(pt: str) -> str:
    return pt + ('X' if len(pt) % 2 else '')

def hill_encrypt(pt: str, K) -> str:
    pt = hill_prepare(pt)
    out = []
    for i in range(0, len(pt), 2):
        p1, p2 = (ALPHA.index(pt[i]), ALPHA.index(pt[i + 1]))
        out.append(ALPHA[(K[0][0] * p1 + K[0][1] * p2) % 26])
        out.append(ALPHA[(K[1][0] * p1 + K[1][1] * p2) % 26])
    return ''.join(out)

def hill_inverse(K):
    det = (K[0][0] * K[1][1] - K[0][1] * K[1][0]) % 26
    inv_det = pow(det, -1, 26)
    return [[K[1][1] * inv_det % 26, -K[0][1] * inv_det % 26], [-K[1][0] * inv_det % 26, K[0][0] * inv_det % 26]]

def hill_decrypt(ct: str, K) -> str:
    return hill_encrypt(ct, hill_inverse(K))

def encrypt(name: str, pt: str, keys: dict) -> str:
    if name == 'Caesar':
        return caesar_encrypt(pt, keys['Caesar'])
    if name == 'Mono':
        return mono_encrypt(pt, keys['Mono'])
    if name == 'Vigenere':
        return vigenere_encrypt(pt, keys['Vigenere'])
    if name == 'Playfair':
        return playfair_encrypt(pt, keys['Playfair'])
    if name == 'Hill':
        return hill_encrypt(pt, keys['Hill'])

def decrypt(name: str, ct: str, keys: dict) -> str:
    if name == 'Caesar':
        return caesar_decrypt(ct, keys['Caesar'])
    if name == 'Mono':
        return mono_decrypt(ct, keys['Mono'])
    if name == 'Vigenere':
        return vigenere_decrypt(ct, keys['Vigenere'])
    if name == 'Playfair':
        return playfair_decrypt(ct, keys['Playfair'])
    if name == 'Hill':
        return hill_decrypt(ct, keys['Hill'])

def expected_after_decrypt(name: str, pt: str) -> str:
    if name == 'Playfair':
        return playfair_prepare(pt)
    if name == 'Hill':
        return hill_prepare(pt)
    return pt

def changed_chars(c1: str, c2: str):
    diff = sum((1 for x, y in zip(c1, c2) if x != y)) + abs(len(c1) - len(c2))
    return (diff, max(len(c1), len(c2)))

def modify_one_char(pt: str) -> str:
    i = len(pt) // 2
    new = 'X' if pt[i] != 'X' else 'Q'
    return pt[:i] + new + pt[i + 1:]

def entropy(text: str) -> float:
    cnt = Counter(text)
    n = len(text)
    return -sum((v / n * math.log2(v / n) for v in cnt.values()))

def find_col(df, keywords, default, exclude=('key',)):
    for c in df.columns:
        lc = c.lower().replace(' ', '_')
        if all((k in lc for k in keywords)) and (not any((e in lc for e in exclude))):
            return c
    return default

def main():
    df = pd.read_csv(INPUT_CSV)
    pt_col = next((c for c in df.columns if 'plaintext' in c.lower() or 'message' in c.lower()), df.columns[0])
    keys = generate_keys(UID)
    with open('keys_used.txt', 'w') as f:
        f.write(f"UID: {UID}\nCaesar key: {keys['Caesar']}\nMono key (shuffled alphabet): {keys['Mono']}\nVigenere keyword: {keys['Vigenere']}\nPlayfair keyword: {keys['PlayfairKeyword']}\nPlayfair matrix:\n" + '\n'.join((' '.join(keys['Playfair'][r * 5:r * 5 + 5]) for r in range(5))) + f"\nHill key: {keys['Hill']}\n")
    print(open('keys_used.txt').read())
    results = {n: [] for n in CIPHERS}
    verified = {n: [] for n in CIPHERS}
    aval = {n: [] for n in CIPHERS}
    changed = {n: [] for n in CIPHERS}
    for raw in df[pt_col]:
        pt = clean(raw)
        pt2 = modify_one_char(pt)
        for n in CIPHERS:
            ct = encrypt(n, pt, keys)
            results[n].append(ct)
            verified[n].append(decrypt(n, ct, keys) == expected_after_decrypt(n, pt))
            diff, total = changed_chars(ct, encrypt(n, pt2, keys))
            changed[n].append(diff)
            aval[n].append(round(diff / total * 100, 2))
    for n in CIPHERS:
        df[find_col(df, [n.lower()[:5], 'cipher'], f'{n}_Ciphertext')] = results[n]
        df[f'{n}_Decryption_Verified'] = verified[n]
        df[f'{n}_Changed_Chars_1CharChange'] = changed[n]
        df[f'{n}_Avalanche_%'] = aval[n]
    df.to_csv(OUTPUT_CSV, index=False)
    print('Decryption verified for all rows:', {n: all(verified[n]) for n in CIPHERS})
    new_uid = UID[:-1] + str((int(UID[-1]) + 1) % 10)
    keys2 = generate_keys(new_uid)
    sample = clean(df[pt_col].iloc[0])
    rows = []
    for n in CIPHERS:
        c1, c2 = (encrypt(n, sample, keys), encrypt(n, sample, keys2))
        d, t = changed_chars(c1, c2)
        rows.append({'Cipher': n, 'Cipher_Key1': c1[:40], 'Cipher_Key2': c2[:40], 'Changed': d, 'Total': t, 'Change_%': round(d / t * 100, 2)})
    parta = pd.DataFrame(rows)
    parta.to_csv('part_a_confusion.csv', index=False)
    print(f'\nPART A (UID {UID} vs {new_uid}) - ciphertext change due to key change')
    print(parta[['Cipher', 'Changed', 'Total', 'Change_%']].to_string(index=False))
    rows = []
    for n in CIPHERS:
        c1, c2 = (encrypt(n, sample, keys), encrypt(n, modify_one_char(sample), keys))
        d, t = changed_chars(c1, c2)
        rows.append({'Cipher': n, 'Changed_Chars': d, 'Total_Chars': t, 'Avalanche_%': round(d / t * 100, 2), 'Avg_Avalanche_%_all_100': round(sum(aval[n]) / len(aval[n]), 2)})
    partbc = pd.DataFrame(rows)
    partbc.to_csv('part_b_c_diffusion_avalanche.csv', index=False)
    print('\nPART B & C - one-character change in plaintext')
    print(partbc.to_string(index=False))
    plt.figure(figsize=(6, 4))
    plt.bar(partbc['Cipher'], partbc['Avg_Avalanche_%_all_100'], color='#5b8def')
    plt.ylabel('Avg avalanche effect (%)')
    plt.title('Avalanche effect (1-char change, all plaintexts)')
    plt.tight_layout()
    plt.savefig('avalanche_avg.png', dpi=150)
    plt.close()
    longest = max(df[pt_col], key=lambda s: len(clean(s)))
    lp = clean(longest)
    pt_cnt = Counter(lp)
    freq_rows = []
    for n in CIPHERS:
        ct = encrypt(n, lp, keys)
        ct_cnt = Counter(ct)
        fig, ax = plt.subplots(1, 2, figsize=(11, 3.6), sharey=True)
        ax[0].bar(list(ALPHA), [pt_cnt.get(ch, 0) for ch in ALPHA], color='#4c78a8')
        ax[0].set_title('Plaintext frequency')
        ax[1].bar(list(ALPHA), [ct_cnt.get(ch, 0) for ch in ALPHA], color='#e45756')
        ax[1].set_title(f'{n} ciphertext frequency')
        for a in ax:
            a.set_xlabel('Letter')
        ax[0].set_ylabel('Count')
        plt.tight_layout()
        plt.savefig(f'freq_{n}.png', dpi=150)
        plt.close()
        freq_rows.append({'Cipher': n, 'Plain_Entropy': round(entropy(lp), 3), 'Cipher_Entropy': round(entropy(ct), 3), 'Max_Letter_%_Plain': round(max(pt_cnt.values()) / len(lp) * 100, 2), 'Max_Letter_%_Cipher': round(max(ct_cnt.values()) / len(ct) * 100, 2)})
    freq = pd.DataFrame(freq_rows)
    print(f'\nPART D - frequency analysis on longest plaintext ({len(lp)} letters); max entropy = {math.log2(26):.3f}')
    print(freq.to_string(index=False))
    print('Lower max-letter % and higher entropy => better concealment of frequency information.')
    inv_hill = sum((1 for a in range(26) for b in range(26) for c in range(26) for d in range(26) if math.gcd((a * d - b * c) % 26, 26) == 1))
    ks = pd.DataFrame([{'Cipher': 'Caesar', 'Key_Space': 25, 'Bits': round(math.log2(25), 1)}, {'Cipher': 'Mono', 'Key_Space': math.factorial(26), 'Bits': round(math.log2(math.factorial(26)), 1)}, {'Cipher': 'Vigenere (5-letter key)', 'Key_Space': 26 ** 5, 'Bits': round(math.log2(26 ** 5), 1)}, {'Cipher': 'Playfair (general 5x5 matrix)', 'Key_Space': math.factorial(25), 'Bits': round(math.log2(math.factorial(25)), 1)}, {'Cipher': 'Hill 2x2', 'Key_Space': inv_hill, 'Bits': round(math.log2(inv_hill), 1)}])
    ks.to_csv('key_space.csv', index=False)
    print('\nPART E - effective key space')
    print(ks.to_string(index=False))
    av = {r['Cipher']: r['Avg_Avalanche_%_all_100'] for r in rows}
    table = pd.DataFrame({'Property': ['Type of Cipher', 'Unit of Encryption', 'Confusion', 'Diffusion', 'Frequency Concealment', 'Avalanche Effect (measured avg %)', 'Key Space', 'Mathematical Operations', 'Overall Security'], 'Caesar': ['Monoalphabetic substitution (shift)', '1 letter', 'Very low', 'None', 'None (distribution only shifted)', av['Caesar'], '25', 'Addition mod 26', 'Very weak'], 'Mono': ['Monoalphabetic substitution', '1 letter', 'Moderate', 'None', 'Poor (frequencies preserved, relabelled)', av['Mono'], '26! (~2^88)', 'Table lookup / permutation', 'Weak (frequency analysis)'], 'Vigenere': ['Polyalphabetic substitution', '1 letter', 'Moderate', 'Very low', 'Moderate (flattened for long keys)', av['Vigenere'], '26^m (26^5 here)', 'Addition mod 26 with repeating key', 'Weak-moderate (Kasiski)'], 'Playfair': ['Polygraphic substitution (digraph)', '2 letters', 'Moderate', 'Low-moderate', 'Good (digraph frequencies)', av['Playfair'], '25! (~2^84)', 'Matrix lookup (row/column/rectangle rules)', 'Moderate'], 'Hill': ['Polygraphic substitution (linear)', '2 letters (n for nxn)', 'Low (linear)', 'Moderate-high within block', 'Good (digraph level)', av['Hill'], f'{inv_hill} (2x2)', 'Matrix multiplication mod 26', 'Moderate (fails to known-plaintext)']})
    table.to_csv('comparative_table.csv', index=False)
    print('\nPART F - comparative table saved to comparative_table.csv')
    print(table.to_string(index=False))
if __name__ == '__main__':
    main()
