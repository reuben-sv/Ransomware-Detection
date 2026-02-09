import numpy as np
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

def train_dynamic_model():
	# ---------------- CONFIG ----------------
	DATASET_PATH = "database/dynamic_training_data.npz"
	MODEL_OUT = "models/Dynamic_Model.pkl"

	TEST_SIZE = 0.2
	RANDOM_STATE = 42

	# ---------------- LOAD DATA ----------------
	print("Loading dataset...")

	data = np.load(DATASET_PATH)
	X = data["X"]
	y = data["y"]

	print("X shape:", X.shape)
	print("y distribution:", {
		0: int((y == 0).sum()),
		1: int((y == 1).sum())
	})

	# ---------------- SPLIT ----------------
	X_train, X_test, y_train, y_test = train_test_split(
		X,
		y,
		test_size=TEST_SIZE,
		random_state=RANDOM_STATE,
		stratify=y
	)

	print("Train size:", X_train.shape[0])
	print("Test size:", X_test.shape[0])

	# ---------------- TRAIN MODEL ----------------
	print("Training Random Forest (Dynamic Analysis)...")

	clf = RandomForestClassifier(
		n_estimators=300,
		max_depth=None,
		min_samples_split=2,
		min_samples_leaf=1,
		n_jobs=-1,
		random_state=RANDOM_STATE
	)

	clf.fit(X_train, y_train)

	# ---------------- EVALUATE ----------------
	print("\nEvaluating model...")

	y_pred = clf.predict(X_test)
	y_proba = clf.predict_proba(X_test)[:, 1]

	print("Accuracy:", round(accuracy_score(y_test, y_pred), 4))
	print("\nClassification Report:")
	print(classification_report(y_test, y_pred, digits=4))

	print("Confusion Matrix:")
	print(confusion_matrix(y_test, y_pred))

	# ---------------- SAVE MODEL ----------------
	joblib.dump(clf, MODEL_OUT)
	print(f"\nDynamic model saved to {MODEL_OUT}")

if __name__ == "__main__":
	train_dynamic_model()