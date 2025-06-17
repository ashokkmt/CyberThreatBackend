import math
import re
from collections import Counter

def shannon_entropy(s):
    if not s:
        return 0
    probabilities = [n_x / len(s) for x, n_x in Counter(s).items()]
    return -sum(p * math.log2(p) for p in probabilities)

def extract_features(s):
    length = len(s)
    entropy = shannon_entropy(s)
    num_quotes = s.count("'") + s.count('"')
    has_script = 1 if "<script>" in s.lower() else 0
    has_sql_keywords = 1 if re.search(r"\b(SELECT|UNION|DROP|--|OR 1=1|INSERT|DELETE|UPDATE)\b", s, re.IGNORECASE) else 0
    special_char_ratio = len(re.findall(r"[^a-zA-Z0-9\s]", s)) / (length + 1e-6)
    return [length, entropy, num_quotes, has_script, has_sql_keywords, special_char_ratio]
