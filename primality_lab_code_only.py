import time
import random
from math import gcd
import pandas as pd
import matplotlib.pyplot as plt
UID = '2022300019'
INPUT_CSV = 'primality_dataset_1000.csv'
OUTPUT_CSV = 'primality_dataset_1000_completed.csv'
random.seed(42)

def generate_bases(uid: str):
    digits = [int(d) for d in uid]
    base1 = int(uid[-2:]) % 97 + 2
    base2 = sum(digits) % 97 + 2
    base3 = (int(uid[:4]) + int(uid[-4:])) % 97 + 2
    base4 = sum(digits[0::2]) % 97 + 2
    base5 = sum(digits[1::2]) % 97 + 2
    return [base1, base2, base3, base4, base5]
BASES = generate_bases(UID)
replaced_log = []

def get_valid_bases(n: int):
    valid = []
    for a in BASES:
        if a < n and gcd(a, n) == 1:
            valid.append(a)
        else:
            new_a = None
            for _ in range(200):
                if n <= 3:
                    break
                cand = random.randint(2, n - 2)
                if gcd(cand, n) == 1 and cand not in valid:
                    new_a = cand
                    break
            if new_a is None:
                return None
            replaced_log.append({'n': n, 'old_base': a, 'new_base': new_a})
            valid.append(new_a)
    return valid

def jacobi(a: int, n: int) -> int:
    a %= n
    result = 1
    while a != 0:
        while a % 2 == 0:
            a //= 2
            if n % 8 in (3, 5):
                result = -result
        a, n = (n, a)
        if a % 4 == 3 and n % 4 == 3:
            result = -result
        a %= n
    return result if n == 1 else 0

def trivial_check(n: int):
    if n < 2:
        return 'Composite'
    if n in (2, 3):
        return 'Prime'
    if n % 2 == 0:
        return 'Composite'
    return None

def fermat_test(n: int) -> str:
    t = trivial_check(n)
    if t is not None:
        return t
    bases = get_valid_bases(n)
    if bases is None:
        return 'Composite'
    for a in bases:
        if pow(a, n - 1, n) != 1:
            return 'Composite'
    return 'Prime'

def euler_test(n: int) -> str:
    t = trivial_check(n)
    if t is not None:
        return t
    bases = get_valid_bases(n)
    if bases is None:
        return 'Composite'
    for a in bases:
        j = jacobi(a, n) % n
        if j == 0:
            return 'Composite'
        if pow(a, (n - 1) // 2, n) != j:
            return 'Composite'
    return 'Prime'

def miller_rabin_test(n: int) -> str:
    t = trivial_check(n)
    if t is not None:
        return t
    bases = get_valid_bases(n)
    if bases is None:
        return 'Composite'
    s, d = (0, n - 1)
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in bases:
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return 'Composite'
    return 'Prime'

def run_test(func, n: int):
    start = time.perf_counter()
    result = func(n)
    end = time.perf_counter()
    return (result, (end - start) * 1000.0)

def main():
    print('UID:', UID, '-> Bases:', BASES)
    df = pd.read_csv(INPUT_CSV)
    num_col = next((c for c in df.columns if c.strip().lower() in ('number', 'n', 'num')))
    type_col = next((c for c in df.columns if c.strip().lower() == 'actual_type'))
    f_res, f_time = ([], [])
    e_res, e_time = ([], [])
    m_res, m_time = ([], [])
    for n in df[num_col]:
        n = int(n)
        r, t = run_test(fermat_test, n)
        f_res.append(r)
        f_time.append(t)
        r, t = run_test(euler_test, n)
        e_res.append(r)
        e_time.append(t)
        r, t = run_test(miller_rabin_test, n)
        m_res.append(r)
        m_time.append(t)
    df['Fermat_Result'], df['Fermat_Time_ms'] = (f_res, f_time)
    df['Euler_Result'], df['Euler_Time_ms'] = (e_res, e_time)
    df['MillerRabin_Result'], df['MillerRabin_Time_ms'] = (m_res, m_time)
    df['Actual_Binary'] = df[type_col].apply(lambda x: 'Prime' if str(x).strip().lower() == 'prime' else 'Composite')
    summary_rows = []
    carmichael_wrong = {}
    for name, res_col, time_col in [('Fermat', 'Fermat_Result', 'Fermat_Time_ms'), ('Euler', 'Euler_Result', 'Euler_Time_ms'), ('Miller-Rabin', 'MillerRabin_Result', 'MillerRabin_Time_ms')]:
        correct = (df[res_col] == df['Actual_Binary']).sum()
        incorrect = len(df) - correct
        fp = ((df[res_col] == 'Prime') & (df['Actual_Binary'] == 'Composite')).sum()
        fn = ((df[res_col] == 'Composite') & (df['Actual_Binary'] == 'Prime')).sum()
        acc = correct / len(df) * 100
        avg_t = df[time_col].mean()
        carm = ((df[type_col].str.strip().str.lower() == 'carmichael') & (df[res_col] == 'Prime')).sum()
        carmichael_wrong[name] = int(carm)
        summary_rows.append({'Algorithm': name, 'Correct': int(correct), 'Incorrect': int(incorrect), 'False Positives': int(fp), 'False Negatives': int(fn), 'Accuracy (%)': round(acc, 2), 'Avg. Time (ms)': round(avg_t, 6)})
    summary = pd.DataFrame(summary_rows)
    print('\n=== SUMMARY TABLE ===')
    print(summary.to_string(index=False))
    print('\nCarmichael numbers wrongly declared Prime:', carmichael_wrong)
    df.drop(columns=['Actual_Binary']).to_csv(OUTPUT_CSV, index=False)
    summary.to_csv('summary_table.csv', index=False)
    pd.DataFrame(replaced_log).to_csv('bases_replaced_log.csv', index=False)
    print(f'\nReplaced bases logged: {len(replaced_log)} (see bases_replaced_log.csv)')

    def bar(col, title, ylabel, fname):
        plt.figure(figsize=(6, 4))
        bars = plt.bar(summary['Algorithm'], summary[col], color=['#d9534f', '#f0ad4e', '#5cb85c'])
        for b in bars:
            plt.text(b.get_x() + b.get_width() / 2, b.get_height(), f'{b.get_height():g}', ha='center', va='bottom')
        plt.title(title)
        plt.ylabel(ylabel)
        plt.tight_layout()
        plt.savefig(fname, dpi=150)
        plt.close()
    bar('Accuracy (%)', 'Accuracy of Each Algorithm', 'Accuracy (%)', 'accuracy.png')
    bar('Avg. Time (ms)', 'Average Execution Time', 'Time (ms)', 'avg_time.png')
    bar('False Positives', 'Number of False Positives', 'Count', 'false_positives.png')
    print('Graphs saved: accuracy.png, avg_time.png, false_positives.png')
if __name__ == '__main__':
    main()
