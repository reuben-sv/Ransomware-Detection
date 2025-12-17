from analysis_modules.static_analysis import analyze_executable_static

# Dynamic analysis will be implemented later
try:
	from analysis_modules.dynamic_analysis import analyze_executable_dynamic
	DYNAMIC_AVAILABLE = True
except ImportError:
	DYNAMIC_AVAILABLE = False


# ---------------- CONFIG ----------------
STATIC_WEIGHT = 0.7
DYNAMIC_WEIGHT = 0.3


# ---------------- SCORE HELPERS ----------------
def static_score_from_probability(prob):
	"""
	Convert static malware probability (0–1)
	to a 0–100 score
	"""
	return int(prob * 100)


def dynamic_score_placeholder():
	"""
	Placeholder for future dynamic analysis.
	Returns None to indicate unavailable.
	"""
	return None


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
	static_label, static_conf = analyze_executable_static(file_path)
	static_score = static_score_from_probability(static_conf)

	print(f"\nStatic analysis score: {static_score}/100")

	# -------- Dynamic analysis (future) --------
	if DYNAMIC_AVAILABLE:
		print("\nRunning dynamic analysis...")
		dynamic_score = analyze_executable_dynamic(file_path)
		print(f"Dynamic analysis score: {dynamic_score}/100")
	else:
		print("\nDynamic analysis not available yet.")
		dynamic_score = dynamic_score_placeholder()

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


# ---------------- ENTRY POINT ----------------
if __name__ == "__main__":
	FILE = ["test_executable_files\\Sample1.exe", "test_executable_files\\Sample2.exe"]
	for file in FILE:
		analyze_file(file)
	
