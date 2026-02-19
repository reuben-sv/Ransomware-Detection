from pathlib import Path
from analysis_modules.static_analysis import analyze_executable_static
from analysis_modules.dynamic_analysis import analyze_executable_dynamic
from train_set_creators.create_dynamic_train_set import create_dynamic_train_set
from train_set_creators.create_static_train_set import create_static_train_set
from model_trainer.train_static_model import train_static_model
from model_trainer.train_dynamic_model import train_dynamic_model
from os.path import isfile
import pandas as pd
from static_analysis_safe_ransomware import static_analysis_safe_ransomware
from enum import Enum
from report_generator import report_generator
# ---------------- CONFIG ----------------
STATIC_WEIGHT = 0.3
DYNAMIC_WEIGHT = 0.7
D = {}
class Status(Enum):
	DEFAULT = 0
	NO_MODEL = -3
	NO_TRAIN_DATA = -2
	NO_DATA = -1
	DATA_FOUND = 1
	TRAIN_DATA_FOUND = 2
	MODEL_FOUND = 3


# ---------------- SCORE HELPERS ----------------
def static_score_from_probability(prob):
	 
	return int(prob * 100)


def dynamic_score_from_probability(prob):
	"""
	Convert dynamic malware probability (0–1)
	to a 0–100 score
	"""
	return int(prob * 100)


def final_ransomware_score(static_score, dynamic_score=None):
	if dynamic_score is None:
		# Only static analysis available
		return static_score

	return int(
		static_score * STATIC_WEIGHT +
		dynamic_score * DYNAMIC_WEIGHT
	)


def verdict_from_score(score):
	if score >= 80:
		return "STRONG RANSOMWARE"
	elif score >= 50:
		return "POSSIBLE / WEAK RANSOMWARE"
	else:
		return "BENIGN"


# ---------------- MAIN ANALYSIS PIPELINE ----------------
def analyze_file(file_path):
	print("=" * 60)

	# -------- Static analysis --------
	print("\nRunning static analysis...")
	static_label, static_conf, static_reasons = analyze_executable_static(file_path, "models/Static_Model.pkl")
	static_score = static_score_from_probability(static_conf)

	print(f"\nStatic analysis score: {static_score}/100")

	# -------- Dynamic analysis --------
	print("\nRunning dynamic analysis...")
	dynamic_prob = analyze_executable_dynamic(file_path)
	dynamic_score = dynamic_score_from_probability(dynamic_prob)
	print(f"Dynamic analysis score: {dynamic_score}/100")

	# -------- Final decision --------
	final_score = final_ransomware_score(static_score, dynamic_score)
	verdict = verdict_from_score(final_score)

	print("\n" + "-" * 40)
	print(f"FINAL RANSOMWARE SCORE: {final_score}/100")
	print(f"VERDICT: {verdict}")
	print("-" * 40)

	return {
		"file_path": file_path,
		"static_reasons": static_reasons,
		"static_score": static_score,
		"dynamic_score": dynamic_score,
		"final_score": final_score,
		"verdict": verdict
	}

def static_model_check():
	static_model_location = "models/Static_Model.pkl"
	if not Path(static_model_location).is_file():
		return Status.NO_MODEL
	else:
		return Status.MODEL_FOUND
	
def dynamic_model_check():
	dynamic_model_location = "models/Dynamic_Model.pkl"
	if not Path(dynamic_model_location).is_file():
		return Status.NO_MODEL
	else:
		return Status.MODEL_FOUND

def static_training_data_check():
	static_model_location = "database/static_training_data.csv"
	if not Path(static_model_location).is_file():
		return Status.NO_TRAIN_DATA
	else:
		return Status.TRAIN_DATA_FOUND

def dynamic_training_data_check():
	dynamic_model_location = "database/dynamic_training_data.npz"
	if not Path(dynamic_model_location).is_file():
		return Status.NO_TRAIN_DATA
	else:
		return Status.TRAIN_DATA_FOUND

def static_data_check():
	r = Status.DATA_FOUND
	static_dataset_location = [
		"database/ember2018/train_features_0.jsonl",
		"database/ember2018/train_features_1.jsonl",
		"database/ember2018/train_features_2.jsonl",
		"database/ember2018/train_features_3.jsonl",
		"database/ember2018/train_features_4.jsonl",
		"database/ember2018/train_features_5.jsonl"
	]
	for path in static_dataset_location:
		if not Path(path).is_file():
			print(f"{path} Not Found")
			r = Status.NO_DATA
			continue
	return r

def dynamic_data_check():
	dynamic_dataset_location = "database/bodmas/bodmas.npz"
	if not Path(dynamic_dataset_location).is_file():
		print(f"{dynamic_dataset_location} Is Missing")
		return Status.NO_DATA
	return Status.DATA_FOUND

# ---------------- ENTRY POINT ----------------
def setup(status):
	# status[0] = Static, status[1] = Dynamic

	# Static 
	print("\nChecking for Static Model: ", end='')
	while status[0] != Status.MODEL_FOUND:
		match status[0]:
			case Status.DEFAULT:
				status[0] = static_model_check()

			case Status.NO_MODEL:
				print("Static Model Not Found")
				print("Checking for Static Training Data: ", end='')
				status[0] = static_training_data_check()

			case Status.NO_TRAIN_DATA:
				print("Static Training Data Not Found")
				print("Checking for Ember Dataset: ", end='')
				status[0] = static_data_check()

			case Status.NO_DATA:
				print("Ember Dataset Incomplete")
				status[0] = Status.NO_DATA
				break
			
			case Status.DATA_FOUND:
				print("Ember Dataset Found")
				print("Creating training set for static analysis model")
				try:
					create_static_train_set()
					status[0] = Status.TRAIN_DATA_FOUND
					print("Static training set Created")
				except Exception as e:
					print("Error:", type(e).__name__, "-", e)

			case Status.TRAIN_DATA_FOUND:
				print("Static Training Data Found")
				print("Training Static Mode (Wait a while)")
				try:
					train_static_model()
					status[0] = Status.MODEL_FOUND
				except Exception as e:
					print("Error:", type(e).__name__, "-", e)

			case Status.MODEL_FOUND:
				print("Static Model Setup Complete")
				break

			case _:
				print("That Should Not Have Happened")

	else:
		print("Static Model Setup Complete")

	# Dynamic
	print("\nChecking for Dynamic Model: ", end= '')
	while status[1] != Status.MODEL_FOUND:
		match status[1]:
			case Status.DEFAULT:
				status[1] = dynamic_model_check()

			case Status.NO_MODEL:
				print("Dynamic Model Not Found")
				print("Checking for Dynamic Training Data: ", end= '')
				status[1] = dynamic_training_data_check()

			case Status.NO_TRAIN_DATA:
				print("Dynamic Training Data Not Found")
				print("Checking for Bodmas Dataset: ", end= '')
				status[1] = dynamic_data_check()

			case Status.NO_DATA:
				print("Bodmas Dataset Missing")
				status[1] = Status.NO_DATA
				break
			
			case Status.DATA_FOUND:
				print("Bodmas Dataset Found")
				print("Creating training set for dynamic analysis model")
				try:
					create_dynamic_train_set()
					status[1] = Status.TRAIN_DATA_FOUND
					print("Dynamic training set Created")
				except Exception as e:
					print("Error:", type(e).__name__, "-", e)

			case Status.TRAIN_DATA_FOUND:
				print("Dynamic Training Data Found")
				print("Training Dynamic Model")
				try:
					train_dynamic_model()
					status[1] = Status.MODEL_FOUND
				except Exception as e:
					print("Error:", type(e).__name__, "-", e)

			case Status.MODEL_FOUND:
				print("Dynamic Model Setup Complete")
				break

			case _:
				print("That Should Not Have Happened")

	else:
		print("Dynamic Model Setup Complete")

	print("\nSetup Completed")
	return status

def analyze():
	file = str(input("Enter Path to executable (.exe) to analyze(Example: C:\\User\\admin\\Downloads\\sample1.exe) : "))
	if not isfile(file):
		print("Path does not exist or is not a file")
		analyze()
	elif not file.lower().endswith(".exe"):
		print("Invalid Path (not .exe type)")
		analyze()
	else:
		return(analyze_file(file))

def showcase():
	CSV_PATH = "database/malware_rows.csv"
	df = pd.read_csv(CSV_PATH, header=None)
	X = df.drop(columns=[0])
	static_analysis_safe_ransomware(X)


def main():
	print("Welcome to the Ransomware Detection System\n Now running Setup")
	menu = True
	while menu == True:
		status = [Status.DEFAULT,Status.DEFAULT]
		print("MENU: ", "0. Setup(Run Once)", "1. ANALYZE EXE", "2. SHOWCASE(featues of 2 real ransomware and a goodware)", "3. EXIT", sep = '\n')
		option = int(input("Option (Enter number): "))
		match option:
			case 0:
				status = setup(status)
			case 1:
				reasons = analyze()
				report_gen = int(input("Generate Report? (0 = No, 1 = Yes) : "))
				if report_gen == 1:
					report_generator(reasons)
			case 2:
				showcase()
			case 3:
				print("Exiting")
				menu = False
				break
			case _:
				print("Invalid Option, try again")
				continue


if __name__ == "__main__":
	main()