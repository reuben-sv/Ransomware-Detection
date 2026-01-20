from pathlib import Path
from analysis_modules.static_analysis import analyze_executable_static
from analysis_modules.dynamic_analysis import analyze_executable_dynamic
from train_set_creators.create_dynamic_train_set import create_dynamic_train_set
from train_set_creators.create_static_train_set import create_static_train_set
from os.path import isfile

# ---------------- CONFIG ----------------
STATIC_WEIGHT = 0.3
DYNAMIC_WEIGHT = 0.7


# ---------------- SCORE HELPERS ----------------
def static_score_from_probability(prob):
	"""
	Convert static malware probability (0–1)
	to a 0–100 score
	"""
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
	static_label, static_conf = analyze_executable_static(file_path)
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
		"static_score": static_score,
		"dynamic_score": dynamic_score,
		"final_score": final_score,
		"verdict": verdict
	}

def main():
	print("RANSOMWARE DETECTION SYSTEM")
	menu = True
	while menu == True:
		print("MENU", "1. SETUP (RUN FIRST)", "2. ANALYZE EXE", "3. SHOWCASE", "4. EXIT", sep = '\n')



# ---------------- ENTRY POINT ----------------
def setup():
	print("Performing Checks:")
	print("Checking for ember dataset")
	#do something
	print("Confirmed")
	print("Checking for Bodmas dataset")
	#do something
	print("Confirmed")

	print("Creating training set for static analysis model")
	create_static_train_set()
	print("Static training set Created")
	print("Creating training set for dynamic analysis model")
	create_dynamic_train_set()
	print("Dynamic training set Created\n")

def analyze():
	file = str(input("Enter Path to executable (.exe) to analyze(Example: C:\\User\\admin\\Downloads\\sample1.exe) : "))
	if not file.lower().endswith(".exe"):
		print("Invalid Path (not .exe type)")
		analyze()
	if not isfile(file):
		print("Path does not exist or is not a file")
	analyze_file(file)

def showcase():
	pass


def main():
	menu = True
	while menu == True:
		print("MENU", "1. SETUP (RUN FIRST)", "2. ANALYZE EXE", "3. SHOWCASE", "4. EXIT", sep = '\n')
		option = int(input("Option: "))
		if option == 1:
			setup()
			continue
		elif option == 2:
			analyze()
		elif option == 3:
			showcase()
		elif option == 4:
			print("Exiting")
			break
		else:
			print("Invalid Option, try again")
			continue


if __name__ == "__main__":
	main()

	
