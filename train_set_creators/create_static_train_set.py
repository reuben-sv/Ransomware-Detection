import json
import pandas as pd

# ---------------- CONFIG ----------------

INPUT_FILES = [
	"database/ember2018/train_features_0.jsonl",
	"database/ember2018/train_features_1.jsonl",
	"database/ember2018/train_features_2.jsonl",
	"database/ember2018/train_features_3.jsonl",
	"database/ember2018/train_features_4.jsonl",
	"database/ember2018/train_features_5.jsonl"
	]
OUTPUT_FILE = "database/ember_static_features.csv"

TOTAL_ROWS = 100000
TARGET_PER_CLASS = TOTAL_ROWS // 2	# 50000 label=0, 50000 label=1

# ---------------- FLATTEN FEATURES ----------------
def flatten_features(sample):
	label = sample.get("label", -1)

	# Skip unlabeled
	if label not in (0, 1):
		return None

	features = {}
	features["label"] = label

	# Histogram
	for i, val in enumerate(sample.get("histogram", [0] * 256)):
		features[f"hist_{i}"] = val

	# Byte entropy
	for i, val in enumerate(sample.get("byteentropy", [0] * 256)):
		features[f"entropy_{i}"] = val

	# General
	general = sample.get("general", {})
	features["general_size"] = general.get("size", 0)
	features["general_vsize"] = general.get("vsize", 0)
	features["general_has_debug"] = general.get("has_debug", 0)
	features["general_exports"] = general.get("exports", 0)
	features["general_imports"] = general.get("imports", 0)
	features["general_has_relocations"] = general.get("has_relocations", 0)
	features["general_has_resources"] = general.get("has_resources", 0)
	features["general_has_signature"] = general.get("has_signature", 0)
	features["general_has_tls"] = general.get("has_tls", 0)
	features["general_symbols"] = general.get("symbols", 0)

	# Header
	header = sample.get("header", {})
	coff = header.get("coff", {})
	optional = header.get("optional", {})

	features["header_coff_timestamp"] = coff.get("timestamp", 0)
	features["header_coff_machine"] = 1 if coff.get("machine") == "I386" else 0
	features["header_coff_characteristics_count"] = len(coff.get("characteristics", []))

	features["header_optional_subsystem"] = 1 if optional.get("subsystem") == "WINDOWS_GUI" else 0
	features["header_optional_dll_characteristics_count"] = len(optional.get("dll_characteristics", []))
	features["header_optional_magic"] = (
		1 if optional.get("magic") == "PE32"
		else 2 if optional.get("magic") == "PE32+" else 0
	)
	features["header_optional_major_linker_version"] = optional.get("major_linker_version", 0)
	features["header_optional_minor_linker_version"] = optional.get("minor_linker_version", 0)
	features["header_optional_major_image_version"] = optional.get("major_image_version", 0)
	features["header_optional_minor_image_version"] = optional.get("minor_image_version", 0)
	features["header_optional_major_os_version"] = optional.get("major_operating_system_version", 0)
	features["header_optional_minor_os_version"] = optional.get("minor_operating_system_version", 0)
	features["header_optional_sizeof_code"] = optional.get("sizeof_code", 0)
	features["header_optional_sizeof_headers"] = optional.get("sizeof_headers", 0)
	features["header_optional_sizeof_heap_commit"] = optional.get("sizeof_heap_commit", 0)

	# Sections
	section = sample.get("section", {})
	sections = section.get("sections", [])

	features["section_count"] = len(sections)
	features["section_entry"] = 1 if section.get("entry") == ".text" else 0

	for i in range(10):
		if i < len(sections):
			s = sections[i]
			features[f"section_{i}_size"] = s.get("size", 0)
			features[f"section_{i}_entropy"] = s.get("entropy", 0)
			features[f"section_{i}_vsize"] = s.get("vsize", 0)
			features[f"section_{i}_props_count"] = len(s.get("props", []))
		else:
			features[f"section_{i}_size"] = 0
			features[f"section_{i}_entropy"] = 0
			features[f"section_{i}_vsize"] = 0
			features[f"section_{i}_props_count"] = 0

	# Imports
	imports = sample.get("imports", {})
	features["imports_dll_count"] = len(imports)
	features["imports_function_count"] = sum(len(v) for v in imports.values())

	common_dlls = [
		"KERNEL32.dll", "USER32.dll", "GDI32.dll", "ADVAPI32.dll",
		"SHELL32.dll", "ole32.dll", "COMCTL32.dll", "WININET.dll",
		"WS2_32.dll", "ntdll.dll"
	]

	for dll in common_dlls:
		features[f"imports_has_{dll.replace('.', '_').lower()}"] = 1 if dll in imports else 0

	for dll in ["KERNEL32.dll", "USER32.dll", "ADVAPI32.dll"]:
		features[f"imports_{dll.replace('.', '_').lower()}_count"] = len(imports.get(dll, []))

	return features

# ---------------- LOAD FILE ----------------

import json
import random
import pandas as pd

def load_all_data(paths):
	data = []

	for path in paths:
		with open(path, "r") as f:
			for line in f:
				sample = json.loads(line)
				features = flatten_features(sample)
				if features is not None:
					data.append(features)

	return data


def balance_data(shuffled_data):
	counts = {0: 0, 1: 0}
	balanced = []

	for row in shuffled_data:
		label = row["label"]

		if counts[label] < TARGET_PER_CLASS:
			balanced.append(row)
			counts[label] += 1

		if counts[0] >= TARGET_PER_CLASS and counts[1] >= TARGET_PER_CLASS:
			break

	return balanced



def load_balanced(path, counts):
	data = []
	with open(path, "r") as f:
		for line in f:
			if counts[0] >= TARGET_PER_CLASS and counts[1] >= TARGET_PER_CLASS:
				break

			sample = json.loads(line)
			features = flatten_features(sample)
			if features is None:
				continue

			label = features["label"]
			if counts[label] < TARGET_PER_CLASS:
				data.append(features)
				counts[label] += 1

	return data

# ---------------- MAIN ----------------
def main():
	print("Loading all data...")
	data = load_all_data(INPUT_FILES)

	print("Shuffling data...")
	random.shuffle(data)

	print("Balancing classes...")
	final_data = balance_data(data)

	df = pd.DataFrame(final_data)

	print("Final dataset shape:", df.shape)
	print("Label distribution:")
	print(df["label"].value_counts())

	df.to_csv(OUTPUT_FILE, index=False)
	print("✓ Saved to", OUTPUT_FILE)


if __name__ == "__main__":
	main()
