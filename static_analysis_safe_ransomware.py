import pandas as pd
import joblib
from treeinterpreter import treeinterpreter as ti
import numpy as np
import warnings
from sklearn.exceptions import DataConversionWarning

warnings.filterwarnings(
	"ignore",
	message="X has feature names, but DecisionTreeClassifier was fitted without feature names"
)


# ---------------- CONFIG ----------------
MODEL_PATH = "models/Static_Model.pkl"
CSV_PATH = "ember_data/malware_rows.csv"  # file containing ONLY those rows
LABEL_COLUMN = 0  # first column is label

# ---------------- LOAD MODEL ----------------
model = joblib.load(MODEL_PATH)

# ---------------- LOAD DATA ----------------
df = pd.read_csv(CSV_PATH, header=None)

# Drop label column
X = df.drop(columns=[LABEL_COLUMN])

# Align column order with model
X.columns = model.feature_names_in_

# ---------------- PREDICT ----------------
proba = model.predict_proba(X)[:, 1]
pred = model.predict(X)

# ---------------- EXPLAIN ----------------
prediction, bias, contributions = ti.predict(model, X)

feature_names = model.feature_names_in_

for i in range(len(X)):
	print(f"\nSample {i+1}")

	score = proba[i]
	print("Malware probability:", round(score, 4))

	if score >= 0.9:
		label = "STRONG RANSOMWARE"
	elif score >= 0.5:
		label = "POSSIBLE/WEAK RANSOMWARE"
	else:
		label = "BENIGN"

	print("Prediction:", label)

	# -------- WHY --------
	contrib = contributions[i]	# shape: (n_features, n_classes)

	feature_contribs = []
	for idx, fname in enumerate(feature_names):
		# Take contribution toward class 1 (malware)
		val = contrib[idx][1]
		feature_contribs.append((fname, val))

	# Sort by absolute impact
	feature_contribs.sort(key=lambda x: abs(x[1]), reverse=True)

	print("\nTop reasons:")

	for fname, val in feature_contribs[:8]:
		direction = "↑ ransomware risk" if val > 0 else "↓ ransomware risk"
		print(f"  {fname}: {val:+.4f} ({direction})")

	print("-" * 50)

