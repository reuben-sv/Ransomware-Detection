import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

def train_static_model():
	# ---------------- CONFIG ----------------
	DATASET_PATH = "database/static_training_data.csv"
	MODEL_OUT = "models\Static_Model.pkl"

	# ---------------- LOAD ----------------
	df = pd.read_csv(DATASET_PATH)

	X = df.drop(columns=["label"])
	y = df["label"]

	# ---------------- SPLIT ----------------
	X_train, X_test, y_train, y_test = train_test_split(
		X,
		y,
		test_size=0.2,
		random_state=42,
		stratify=y
	)

	# ---------------- TRAIN ----------------
	clf = RandomForestClassifier(
		n_estimators=300,
		n_jobs=-1,
		random_state=42
	)

	clf.fit(X_train, y_train)

	# ---------------- EVAL ----------------
	y_pred = clf.predict(X_test)

	print("Accuracy:", accuracy_score(y_test, y_pred))
	print(classification_report(y_test, y_pred))

	# ---------------- SAVE ----------------
	joblib.dump(clf, MODEL_OUT)
	print("Model saved as", MODEL_OUT)

if __name__ == "__main__":
	train_static_model()
