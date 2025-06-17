import pandas as pd
import math
import re
from collections import Counter
from xgboost import XGBClassifier
import joblib

# 📥 Step 1: Load your dataset
df = pd.read_csv("final_dataset.csv")

# 🧠 Step 2: Feature extraction
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

# ✅ Apply feature extraction
features = df["input"].apply(extract_features).tolist()
feature_df = pd.DataFrame(features, columns=[
    "length", "entropy", "num_quotes", "has_script",
    "has_sql_keywords", "special_char_ratio"
])

# 🔗 Step 3: Combine features with original data
final_df = pd.concat([df, feature_df], axis=1)
final_df.to_csv("final_dataset_with_features.csv", index=False)
print("✅ Saved dataset with features to final_dataset_with_features.csv")

# 🧠 Step 4: Train the model
X = feature_df
y = df["label"]

model = XGBClassifier(objective='multi:softmax', num_class=3)
model.fit(X, y)

# 💾 Step 5: Save the model
joblib.dump(model, "attack_classifier.pkl")
print("✅ Model trained and saved to attack_classifier.pkl")
