import joblib
import numpy as np
import pandas as pd
import analysis_modules.extract_static_features as esf

# ---------------- CONFIG ----------------
MODEL_PATH = "models/Static_Model.pkl"

# ---------------- LOAD MODEL (once) ----------------
_model = joblib.load(MODEL_PATH)


# ---------------- FEATURE FLATTENER ----------------
def flatten_exe_features(raw):
	vec = []

	# Histogram
	for v in raw["histogram"]:
		vec.append(v)

	# Byte entropy
	for v in raw["byteentropy"]:
		vec.append(v)

	# General
	g = raw["general"]
	vec.extend([
		g.get("size", 0),
		g.get("vsize", 0),
		g.get("has_debug", 0),
		g.get("exports", 0),
		g.get("imports", 0),
		g.get("has_relocations", 0),
		g.get("has_resources", 0),
		g.get("has_signature", 0),
		g.get("has_tls", 0),
		g.get("symbols", 0),
	])

	# Header
	h = raw.get("header", {})
	coff = h.get("coff", {})
	opt = h.get("optional", {})

	vec.append(coff.get("timestamp", 0))
	vec.append(1 if coff.get("machine") == "I386" else 0)
	vec.append(len(coff.get("characteristics", [])))

	vec.append(1 if opt.get("subsystem") == "WINDOWS_GUI" else 0)
	vec.append(len(opt.get("dll_characteristics", [])))
	vec.append(1 if opt.get("magic") == "PE32" else 2 if opt.get("magic") == "PE32+" else 0)
	vec.append(opt.get("major_linker_version", 0))
	vec.append(opt.get("minor_linker_version", 0))
	vec.append(opt.get("major_image_version", 0))
	vec.append(opt.get("minor_image_version", 0))
	vec.append(opt.get("major_operating_system_version", 0))
	vec.append(opt.get("minor_operating_system_version", 0))
	vec.append(opt.get("sizeof_code", 0))
	vec.append(opt.get("sizeof_headers", 0))
	vec.append(opt.get("sizeof_heap_commit", 0))

	# Sections (up to 10)
	secs = raw.get("section", {}).get("sections", [])
	vec.append(len(secs))
	vec.append(1 if raw.get("section", {}).get("entry") == ".text" else 0)

	for i in range(10):
		if i < len(secs):
			s = secs[i]
			vec.append(s.get("size", 0))
			vec.append(s.get("entropy", 0))
			vec.append(s.get("vsize", 0))
			vec.append(len(s.get("props", [])))
		else:
			vec.extend([0, 0, 0, 0])

	# Imports
	imps = raw.get("imports", {})
	vec.append(len(imps))
	vec.append(sum(len(v) for v in imps.values()))

	common_dlls = [
		"KERNEL32.dll", "USER32.dll", "GDI32.dll", "ADVAPI32.dll",
		"SHELL32.dll", "ole32.dll", "COMCTL32.dll", "WININET.dll",
		"WS2_32.dll", "ntdll.dll"
	]

	for dll in common_dlls:
		vec.append(1 if dll in imps else 0)

	for dll in ["KERNEL32.dll", "USER32.dll", "ADVAPI32.dll"]:
		vec.append(len(imps.get(dll, [])))

	return np.array(vec).reshape(1, -1)


# ---------------- PUBLIC API FUNCTION ----------------
def analyze_executable_static(file_path):
	print(f"\nAnalyzing: {file_path}")
	print(f"Extracting features from {file_path}")

	raw_features = esf.extract_pe_features(file_path)

	# Histogram preview
	hist = raw_features["histogram"]
	print(f"\nHistogram:")
	print(f"  Length: {len(hist)}")
	print(f"  First 16 values: {hist[:16]}")
	print(f"  Min / Max: {min(hist)} / {max(hist)}")

	# Byte entropy preview
	ent = raw_features["byteentropy"]
	print(f"\nByte Entropy:")
	print(f"  Length: {len(ent)}")
	print(f"  First 16 values: {ent[:16]}")
	print(f"  Non-zero bins: {sum(1 for v in ent if v > 0)}")

	# General
	print(f"\nGeneral:")
	for k, v in raw_features["general"].items():
		print(f"  {k}: {v}")

	# Sections
	secs = raw_features.get("section", {}).get("sections", [])
	print(f"\nSections:")
	print(f"  Count: {len(secs)}")
	for i, s in enumerate(secs[:3]):
		print(f"  Section {i}: size={s.get('size')}, vsize={s.get('vsize')}, entropy={s.get('entropy'):.2f}")

	# Imports
	imps = raw_features.get("imports", {})
	print(f"\nImports:")
	print(f"  DLL count: {len(imps)}")
	for dll, funcs in list(imps.items())[:3]:
		print(f"  {dll}: {len(funcs)} functions")


	print("\nModel predicting based on extracted features")

	flat = flatten_exe_features(raw_features)

	X = pd.DataFrame(
		flat,
		columns=_model.feature_names_in_
	)

	pred = _model.predict(X)[0]
	proba = _model.predict_proba(X)[0][pred]

	print("Prediction complete")

	label = "MALWARE / RANSOMWARE" if pred == 1 else "BENIGN"

	return label, float(proba)
