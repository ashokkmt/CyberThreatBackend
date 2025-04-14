import re

# FSM-style pattern-based detection for common XSS attack markers
def contains_xss_patterns(input_str):
    input_str = input_str.lower()

    dangerous_keywords = [
        "<script>", "</script>",
        "onerror=", "onload=", "onclick=",
        "javascript:"
    ]

    for keyword in dangerous_keywords:
        if keyword in input_str:
            return True, keyword

    return False, None


def is_valid_sql(input_str):
    input_str = input_str.lower()

    # Count SQL keywords (but allow 1 or 2 if they're not structured)
    sql_keywords = ["select", "insert", "update", "delete", "drop", "create", "alter", "union"]
    keyword_count = sum(1 for kw in sql_keywords if kw in input_str)

    # If it's just a single word like "select" in a normal string, it's fine
    if keyword_count <= 1 and not re.search(r"(from|where|or\s+1=1|--|;)", input_str):
        return True

    # Match known SQL injection patterns
    attack_patterns = [
        r"(\bor\b|\band\b)\s+\d+=\d+",             # OR 1=1
        r"['\"]\s*or\s*['\"]?1['\"]?\s*=\s*['\"]?1",# ' or '1'='1
        r"['\"].*--",                              # Inline comment after quote
        r";\s*(drop|delete|truncate|update)\b",    # Stacked query
        r"\bunion\b.*\bselect\b",                  # UNION SELECT
        r"\bexec(\s|\+)+(s|x)p\w+",                # Stored procs
        r"drop\s+table",                           # DROP TABLE
        r"['\"]{2,}",                              # Repeated quotes
    ]

    for pattern in attack_patterns:
        if re.search(pattern, input_str):
            print(f"⚠️ SQL Injection pattern matched: {pattern}")
            return False

    return True


# XSS FSM: detect script tags
def contains_script_tag(input_str):
    input_str = input_str.lower()
    return "<script>" in input_str and "</script>" in input_str

