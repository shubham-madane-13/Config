"""
Lab Assignment: Comparative Analysis of Asymmetric Cryptographic Algorithms
Algorithms : RSA, ElGamal, Diffie-Hellman, Elliptic Curve Cryptography (ECC)
Input      : asymmetric_cipher_dataset.xlsx   (~100 messages)
Output     : asymmetric_cipher_dataset_completed.xlsx  (dataset + all analysis tables as sheets)
             rsa_vs_ecc_keysize.png (line graph), capability_radar.png (radar chart),
             discussion_answers.md (answers to the discussion questions)
Only the Python standard library + pandas, openpyxl, matplotlib are needed (all maths is hand-coded).
"""

import random
import math
import time
import hashlib
import pandas as pd
import matplotlib.pyplot as plt

UID = "2024300020"
INPUT_XLSX = "asymmetric_cipher_dataset.xlsx"
OUTPUT_XLSX = "asymmetric_cipher_dataset_completed.xlsx"
RSA_PRIME_BITS = 64
ELGAMAL_PRIME_BITS = 128
DH_PRIME_BITS = 128
rng = random.Random(int(UID))

SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71]

def is_prime(n: int) -> bool:
    """Miller-Rabin primality test (strong probable prime to 20 fixed bases)."""
    if n < 2:
        return False
    for p in SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in SMALL_PRIMES:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def gen_prime(bits: int) -> int:
    """Random prime with exactly `bits` bits, drawn from the UID-seeded generator."""
    while True:
        x = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(x):
            return x

def gen_safe_prime(bits: int):
    """Safe prime p = 2q+1 (q also prime). Makes finding a generator easy. Returns (p, q)."""
    while True:
        q = gen_prime(bits - 1)
        p = 2 * q + 1
        if is_prime(p):
            return p, q

def find_generator(p: int, q: int) -> int:
    """Primitive root of safe prime p=2q+1: g is a generator iff g^2 != 1 and g^q != 1 (mod p)."""
    while True:
        g = rng.randrange(2, p - 1)
        if pow(g, 2, p) != 1 and pow(g, q, p) != 1:
            return g

def to_blocks(msg, block_bytes: int):
    """Convert a message (text or integer) into a list of integers, each < modulus."""
    if isinstance(msg, (int,)) or (hasattr(msg, "item") and float(msg).is_integer()):
        return [int(msg)], True
    data = str(msg).encode("utf-8")
    blocks = [int.from_bytes(data[i:i + block_bytes], "big") for i in range(0, len(data), block_bytes)]
    return blocks, False

def from_blocks(blocks, numeric: bool):
    """Inverse of to_blocks: integers back to the original message."""
    if numeric:
        return blocks[0]
    out = b""
    for m in blocks:
        out += m.to_bytes((m.bit_length() + 7) // 8, "big")
    return out.decode("utf-8", errors="replace")

def rsa_keygen(bits: int):
    """Generate p, q, n, phi, e, d as in section 5.1."""
    p = gen_prime(bits)
    q = gen_prime(bits)
    while q == p:
        q = gen_prime(bits)
    n, phi = p * q, (p - 1) * (q - 1)
    e = 65537
    while math.gcd(e, phi) != 1:
        e = rng.randrange(3, phi, 2)
    d = pow(e, -1, phi)
    return {"p": p, "q": q, "n": n, "phi": phi, "e": e, "d": d}

def rsa_encrypt(blocks, e, n):
    return [pow(m, e, n) for m in blocks]

def rsa_decrypt(cblocks, d, n):
    return [pow(c, d, n) for c in cblocks]

def elgamal_keygen(bits: int):
    """Generate p, g, private x and public y = g^x mod p (section 5.2)."""
    p, q = gen_safe_prime(bits)
    g = find_generator(p, q)
    x = rng.randrange(2, p - 2)
    y = pow(g, x, p)
    return {"p": p, "g": g, "x": x, "y": y}

def elgamal_encrypt(blocks, key):
    """For each block pick a fresh ephemeral k: c1 = g^k, c2 = m * y^k (mod p)."""
    p, g, y = key["p"], key["g"], key["y"]
    ks, cts = [], []
    for m in blocks:
        k = rng.randrange(2, p - 2)
        cts.append((pow(g, k, p), (m * pow(y, k, p)) % p))
        ks.append(k)
    return cts, ks

def elgamal_decrypt(cts, key):
    p, x = key["p"], key["x"]

    return [(c2 * pow(pow(c1, x, p), -1, p)) % p for c1, c2 in cts]

def dh_params(bits: int):
    p, q = gen_safe_prime(bits)
    g = find_generator(p, q)
    return p, g

def dh_session(p, g):
    a = rng.randrange(2, p - 2)
    b = rng.randrange(2, p - 2)
    A, B = pow(g, a, p), pow(g, b, p)
    KA, KB = pow(B, a, p), pow(A, b, p)
    return a, A, b, B, KA, KB, KA == KB

CURVE_NAME = "secp256k1"
P = 2 ** 256 - 2 ** 32 - 977
A_COEF, B_COEF = 0, 7
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)
N_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def ec_add(P1, P2):
    """Add two points (None = point at infinity)."""
    if P1 is None: return P2
    if P2 is None: return P1
    (x1, y1), (x2, y2) = P1, P2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if P1 == P2:
        lam = (3 * x1 * x1 + A_COEF) * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)

def ec_mul(k, pt):
    """Scalar multiplication k*pt by double-and-add."""
    result = None
    addend = pt
    while k:
        if k & 1:
            result = ec_add(result, addend)
        addend = ec_add(addend, addend)
        k >>= 1
    return result

def keystream_xor(data: bytes, shared_point) -> bytes:
    """ECIES-style: key = SHA256(x of shared point), expanded with a counter, XORed with data."""
    out = bytearray()
    for i in range(0, len(data), 32):
        ks = hashlib.sha256(shared_point[0].to_bytes(32, "big") + i.to_bytes(4, "big")).digest()
        out += bytes(b ^ k for b, k in zip(data[i:i + 32], ks))
    return bytes(out)

def norm(s):
    return "".join(ch for ch in str(s).lower() if ch.isalnum())

def put(df, name, values):
    """Write values into an existing (matching) column, or create a new one."""
    for c in df.columns:
        if norm(c) == norm(name):
            df[c] = values
            return
    df[name] = values

def timed(func, *a):
    t = time.perf_counter()
    r = func(*a)
    return r, (time.perf_counter() - t) * 1000

def main():
    df = pd.read_excel(INPUT_XLSX)
    msg_col = next((c for c in df.columns if "message" in str(c).lower() or "plain" in str(c).lower()), df.columns[0])
    messages = list(df[msg_col])

    rsa = rsa_keygen(RSA_PRIME_BITS)
    eg = elgamal_keygen(ELGAMAL_PRIME_BITS)
    dh_p, dh_g = dh_params(DH_PRIME_BITS)
    d_ecc = rng.randrange(1, N_ORDER)
    Q = ec_mul(d_ecc, G)
    assert ec_mul(N_ORDER, G) is None, "base point order check failed"

    rsa_block = (rsa["n"].bit_length() - 1) // 8
    eg_block = (eg["p"].bit_length() - 1) // 8

    cols = {k: [] for k in [
        "RSA_p", "RSA_q", "RSA_n", "RSA_phi", "RSA_e", "RSA_d", "RSA_Ciphertext", "RSA_Decrypted", "RSA_Verified", "RSA_Time_ms",
        "EG_p", "EG_g", "EG_Private_x", "EG_Public_y", "EG_k", "EG_Ciphertext", "EG_Decrypted", "EG_Verified", "EG_Time_ms",
        "DH_p", "DH_g", "DH_Alice_Private", "DH_Alice_Public", "DH_Bob_Private", "DH_Bob_Public",
        "DH_Alice_Secret", "DH_Bob_Secret", "DH_Match", "DH_Time_ms",
        "ECC_Curve", "ECC_G", "ECC_Private_d", "ECC_Public_Q", "ECC_k", "ECC_R", "ECC_Ciphertext_hex",
        "ECC_Decrypted", "ECC_Verified", "ECC_Time_ms", "Observations"]}

    for msg in messages:
        blocks, numeric = to_blocks(msg, min(rsa_block, eg_block))

        c, t1 = timed(rsa_encrypt, blocks, rsa["e"], rsa["n"])
        m, t2 = timed(rsa_decrypt, c, rsa["d"], rsa["n"])
        rsa_dec = from_blocks(m, numeric)
        for k in ("p", "q", "n", "phi", "e", "d"):
            cols["RSA_" + k].append(rsa[k])
        cols["RSA_Ciphertext"].append(",".join(map(str, c)))
        cols["RSA_Decrypted"].append(rsa_dec)
        cols["RSA_Verified"].append(rsa_dec == (msg if numeric else str(msg)) or m == blocks)
        cols["RSA_Time_ms"].append(round(t1 + t2, 4))

        (cts, ks), t1 = timed(elgamal_encrypt, blocks, eg)
        m, t2 = timed(elgamal_decrypt, cts, eg)
        eg_dec = from_blocks(m, numeric)
        cols["EG_p"].append(eg["p"]); cols["EG_g"].append(eg["g"])
        cols["EG_Private_x"].append(eg["x"]); cols["EG_Public_y"].append(eg["y"])
        cols["EG_k"].append(",".join(map(str, ks)))
        cols["EG_Ciphertext"].append(";".join(f"({a},{b})" for a, b in cts))
        cols["EG_Decrypted"].append(eg_dec)
        cols["EG_Verified"].append(m == blocks)
        cols["EG_Time_ms"].append(round(t1 + t2, 4))

        (a, A, b, B, KA, KB, ok), t = timed(dh_session, dh_p, dh_g)
        for key, val in zip(["DH_p", "DH_g", "DH_Alice_Private", "DH_Alice_Public", "DH_Bob_Private", "DH_Bob_Public",
                             "DH_Alice_Secret", "DH_Bob_Secret", "DH_Match", "DH_Time_ms"],
                            [dh_p, dh_g, a, A, b, B, KA, KB, ok, round(t, 4)]):
            cols[key].append(val)

        raw = str(msg).encode("utf-8")
        t0 = time.perf_counter()
        k = rng.randrange(1, N_ORDER)
        R = ec_mul(k, G)
        ct = keystream_xor(raw, ec_mul(k, Q))
        S2 = ec_mul(d_ecc, R)
        pt = keystream_xor(ct, S2)
        t = (time.perf_counter() - t0) * 1000
        cols["ECC_Curve"].append(CURVE_NAME); cols["ECC_G"].append(f"({hex(GX)[:12]}..., {hex(GY)[:12]}...)")
        cols["ECC_Private_d"].append(d_ecc); cols["ECC_Public_Q"].append(f"({hex(Q[0])[:14]}..., {hex(Q[1])[:14]}...)")
        cols["ECC_k"].append(k); cols["ECC_R"].append(f"({hex(R[0])[:14]}..., {hex(R[1])[:14]}...)")
        cols["ECC_Ciphertext_hex"].append(ct.hex()); cols["ECC_Decrypted"].append(pt.decode("utf-8", errors="replace"))
        cols["ECC_Verified"].append(pt == raw); cols["ECC_Time_ms"].append(round(t, 4))

        cols["Observations"].append(f"{len(blocks)} block(s); RSA ct {len(c)} int(s); ElGamal ct {2 * len(cts)} ints (2x expansion); "
                                    f"ECC ct {len(ct)} bytes + point R")

    for name, vals in cols.items():
        put(df, name, vals)

    verify = {"RSA": all(cols["RSA_Verified"]), "ElGamal": all(cols["EG_Verified"]),
              "Diffie-Hellman": all(cols["DH_Match"]), "ECC": all(cols["ECC_Verified"])}
    print("UID:", UID)
    print("RSA  : n bits =", rsa["n"].bit_length(), " e =", rsa["e"])
    print("ElGamal p bits =", eg["p"].bit_length(), "  DH p bits =", dh_p.bit_length(), "  ECC curve =", CURVE_NAME)
    print("All records verified:", verify)

    timing = pd.DataFrame({
        "Algorithm": ["RSA", "ElGamal", "Diffie-Hellman", "ECC (ECIES)"],
        "Key_Size_bits": [rsa["n"].bit_length(), eg["p"].bit_length(), dh_p.bit_length(), 256],
        "Avg_Time_ms_per_record": [round(sum(cols[k]) / len(messages), 4) for k in
                                   ["RSA_Time_ms", "EG_Time_ms", "DH_Time_ms", "ECC_Time_ms"]],
        "All_Verified": [verify["RSA"], verify["ElGamal"], verify["Diffie-Hellman"], verify["ECC"]]})
    print(timing.to_string(index=False))

    params = pd.DataFrame([
        ["UID", UID], ["RSA p", rsa["p"]], ["RSA q", rsa["q"]], ["RSA n", rsa["n"]], ["RSA phi(n)", rsa["phi"]],
        ["RSA e", rsa["e"]], ["RSA d", rsa["d"]], ["ElGamal p", eg["p"]], ["ElGamal g", eg["g"]],
        ["ElGamal private x", eg["x"]], ["ElGamal public y", eg["y"]], ["DH p", dh_p], ["DH g", dh_g],
        ["ECC curve", f"{CURVE_NAME}: y^2 = x^3 + 7 over GF(2^256 - 2^32 - 977)"], ["ECC G.x", hex(GX)], ["ECC G.y", hex(GY)],
        ["ECC order n", hex(N_ORDER)], ["ECC private d", d_ecc], ["ECC public Q.x", hex(Q[0])], ["ECC public Q.y", hex(Q[1])]],
        columns=["Parameter", "Value"])

    math_found = pd.DataFrame({
        "Property": ["Mathematical Basis", "Large Prime Required", "Modular Arithmetic", "Elliptic Curve Operations", "Main Hard Problem"],
        "RSA": ["Number theory: Euler's theorem, modular exponentiation", "Yes - two large primes p, q", "Yes (mod n = pq)", "No", "Integer factorization"],
        "ElGamal": ["Cyclic group Z*_p, discrete log", "Yes - one large prime p", "Yes (mod p)", "No", "Discrete logarithm problem (DLP)"],
        "Diffie-Hellman": ["Cyclic group Z*_p, exponentiation is commutative", "Yes - one large (safe) prime p", "Yes (mod p)", "No (classic DH)", "DLP / Diffie-Hellman problem (CDH)"],
        "ECC": ["Group of points on an elliptic curve over GF(p)", "Yes - field prime (curve order also prime)", "Yes (field arithmetic mod p)", "Yes - point addition, doubling, scalar multiplication", "Elliptic Curve DLP (ECDLP)"]})
    security = pd.DataFrame({
        "Algorithm": ["RSA", "ElGamal", "Diffie-Hellman", "ECC"],
        "Underlying Hard Problem": ["Integer Factorization", "Discrete Logarithm", "Discrete Logarithm / Diffie-Hellman Problem", "Elliptic Curve Discrete Logarithm"],
        "Why breaking it compromises security": [
            "Factoring n gives p and q, so phi(n) and then d = e^-1 mod phi are computed -> private key recovered.",
            "Solving y = g^x mod p for x reveals the private key, so every ciphertext can be decrypted.",
            "Finding a or b from A or B (or computing g^ab from g^a, g^b) reveals the shared secret.",
            "Finding d from Q = dG reveals the private key; no sub-exponential attack is known, unlike factoring/DLP in Z*_p."]})
    sec_levels = [80, 112, 128, 192, 256]
    rsa_bits = [1024, 2048, 3072, 7680, 15360]
    ecc_bits = [160, 224, 256, 384, 512]
    keysize = pd.DataFrame({"Security Level (bits)": sec_levels, "RSA key size (bits)": rsa_bits,
                            "ECC key size (bits)": ecc_bits, "Ratio RSA/ECC": [round(r / e, 1) for r, e in zip(rsa_bits, ecc_bits)]})
    key_mgmt = pd.DataFrame({
        "Property": ["Public Key", "Private Key", "Encryption", "Decryption", "Key Exchange", "Shared Secret", "Requires Public Parameters"],
        "RSA": ["(e, n)", "(d, n)", "C = M^e mod n", "M = C^d mod n", "Possible (encrypt a session key)", "No (key transport)", "No - only (e, n)"],
        "ElGamal": ["(p, g, y)", "x", "(g^k, m*y^k) mod p", "m = c2 * (c1^x)^-1 mod p", "Not primary use", "No", "Yes - p, g"],
        "Diffie-Hellman": ["A = g^a mod p, B = g^b mod p", "a (Alice), b (Bob)", "Not provided", "Not provided", "Yes - primary purpose", "K = g^ab mod p", "Yes - p, g"],
        "ECC": ["Q = dG", "d", "ECIES / EC-ElGamal", "ECIES / EC-ElGamal decrypt", "Yes - ECDH", "dA*QB = dB*QA", "Yes - curve, G, n"]})
    purpose = pd.DataFrame({
        "Algorithm": ["RSA", "ElGamal", "Diffie-Hellman", "ECC"],
        "Encryption": ["Yes", "Yes", "No", "Yes (ECIES / EC-ElGamal)"],
        "Key Exchange": ["Yes (key transport)", "Limited", "Yes (primary)", "Yes (ECDH)"],
        "Why": ["Direct encryption of small data and digital signatures", "Randomised encryption; ciphertext 2x larger", "Only agrees a shared secret K; there is no message input, so a symmetric cipher must use K", "Provides ECDH, ECDSA and ECIES with small keys"]})
    ratings = pd.DataFrame({
        "Parameter": ["Key Generation Complexity (5 = most complex)", "Mathematical Complexity (5 = most complex)", "Key Size Efficiency",
                      "Encryption Capability", "Key Exchange Capability", "Scalability", "Suitability for Resource-Constrained Devices",
                      "Overall Practical Suitability"],
        "RSA": [4, 3, 1, 4, 3, 3, 2, 4], "ElGamal": [3, 3, 1, 4, 2, 2, 1, 2], "DH": [2, 3, 1, 1, 5, 3, 2, 4], "ECC": [2, 5, 5, 3, 5, 5, 5, 5],
        "Justification": [
            "RSA needs two large primes (costly search); ElGamal/DH need one safe prime; ECC keys are just a random scalar.",
            "ECC uses abstract group laws on curves; the others use plain modular arithmetic.",
            "ECC gives 128-bit security with 256-bit keys; RSA/ElGamal/DH need ~3072 bits.",
            "RSA and ElGamal encrypt directly; ECC needs a hybrid scheme (ECIES); DH cannot encrypt.",
            "DH/ECDH are designed for it; RSA can transport a key; ElGamal rarely used for this.",
            "ECC keeps keys, signatures and bandwidth small as security grows; RSA grows very fast.",
            "ECC has small keys, less memory and power; ElGamal has large keys and 2x ciphertext.",
            "TLS 1.3 prefers ECDHE + ECDSA/EdDSA; RSA still common; ElGamal is rare today."]})

    with pd.ExcelWriter(OUTPUT_XLSX, engine="openpyxl") as xw:
        df.to_excel(xw, sheet_name="Dataset_Completed", index=False)
        params.to_excel(xw, sheet_name="Parameters_Used", index=False)
        timing.to_excel(xw, sheet_name="Summary_Timing", index=False)
        math_found.to_excel(xw, sheet_name="7A_Math_Foundation", index=False)
        security.to_excel(xw, sheet_name="7B_Security_Assumption", index=False)
        keysize.to_excel(xw, sheet_name="8_Key_Size", index=False)
        key_mgmt.to_excel(xw, sheet_name="9_Key_Management", index=False)
        purpose.to_excel(xw, sheet_name="10_Enc_vs_KeyExchange", index=False)
        ratings.to_excel(xw, sheet_name="11_Comparative_Ratings", index=False)

    plt.figure(figsize=(6.5, 4.2))
    plt.plot(sec_levels, rsa_bits, "o-", label="RSA")
    plt.plot(sec_levels, ecc_bits, "s-", label="ECC")
    for x, r, e in zip(sec_levels, rsa_bits, ecc_bits):
        plt.annotate(str(r), (x, r), textcoords="offset points", xytext=(-8, 6), fontsize=8)
        plt.annotate(str(e), (x, e), textcoords="offset points", xytext=(0, 6), fontsize=8)
    plt.xlabel("Security level (bits)"); plt.ylabel("Key size (bits)")
    plt.title("RSA vs ECC key size for equivalent security"); plt.legend(); plt.grid(alpha=.3)
    plt.tight_layout(); plt.savefig("rsa_vs_ecc_keysize.png", dpi=150); plt.close()

    cap = ratings.iloc[2:]
    labels = ["Key size\nefficiency", "Encryption", "Key\nexchange", "Scalability", "Constrained\ndevices", "Overall"]
    ang = [i / len(labels) * 2 * math.pi for i in range(len(labels))]; ang += ang[:1]
    fig = plt.figure(figsize=(6.2, 6.2)); ax = plt.subplot(111, polar=True)
    for alg in ["RSA", "ElGamal", "DH", "ECC"]:
        vals = list(cap[alg]) + [cap[alg].iloc[0]]
        ax.plot(ang, vals, label=alg); ax.fill(ang, vals, alpha=.08)
    ax.set_xticks(ang[:-1]); ax.set_xticklabels(labels); ax.set_ylim(0, 5)
    ax.set_title("Algorithm capability comparison (1 = low, 5 = high)", y=1.08)
    ax.legend(loc="upper right", bbox_to_anchor=(1.25, 1.1))
    plt.tight_layout(); plt.savefig("capability_radar.png", dpi=150); plt.close()

    with open("discussion_answers.md", "w", encoding="utf-8") as f:
        f.write(DISCUSSION)
    print("\nSaved:", OUTPUT_XLSX, "| rsa_vs_ecc_keysize.png | capability_radar.png | discussion_answers.md")

DISCUSSION = """# Discussion Answers

1. **Why two primes in RSA?** n = pq is easy to compute but hard to factor. Knowing p and q gives phi(n) = (p-1)(q-1), needed to compute d. With one prime, phi(n) = p-1 would be public and d trivially computed.
2. **Why gcd(e, phi) = 1?** e must have an inverse mod phi(n) so that d exists with ed = 1 (mod phi). Otherwise decryption is impossible/ambiguous.
3. **Why is prime generation important?** Weak, small or special-form primes can be factored (RSA) or make discrete logs easy (ElGamal/DH, e.g. Pohlig-Hellman when p-1 is smooth). Primes must be large, random and (for DH/ElGamal) safe.
4. **RSA security basis:** the integer factorization problem (RSA problem).
5. **ElGamal and DH basis:** the discrete logarithm problem (and CDH/DDH assumptions for DH).
6. **DH without sending the secret:** only g^a and g^b travel over the network. Each side raises the other's public value to its own private exponent to get g^ab; an eavesdropper would have to solve a discrete log.
7. **DH does not encrypt:** it only produces a shared value K; it has no message input or ciphertext. K is used as (or to derive) a key for a symmetric cipher such as AES.
8. **ECC small keys:** the best known attacks on ECDLP are fully exponential (~sqrt(n), Pollard rho), whereas factoring and finite-field DLP have sub-exponential attacks (number field sieve / index calculus). So each ECC bit gives more security: 256-bit ECC ~ 3072-bit RSA.
9. **Resource-constrained devices:** ECC (e.g. X25519 / ECDH + ECDSA). Smaller keys, signatures and ciphertext, less RAM, faster key generation and lower power.
10. **Why hybrid?** Asymmetric operations are slow and have message-size limits; symmetric ciphers are fast. So asymmetric crypto (DH/ECDH/RSA) securely agrees a key, and a symmetric cipher (AES/ChaCha20) encrypts bulk data (TLS, PGP, ECIES).
"""

if __name__ == "__main__":
    main()

