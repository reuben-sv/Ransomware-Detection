import pefile
import numpy as np
import math

# ---------------- BYTE FEATURES ----------------

def byte_histogram(data):
	hist = np.zeros(256, dtype=int)
	for b in data:
		hist[b] += 1
	return hist.tolist()

def byte_entropy(data, window=2048, step=1024):
	bins = np.zeros((16, 16), dtype=int)

	for i in range(0, len(data) - window, step):
		block = data[i:i + window]
		if not block:
			continue

		block_arr = np.frombuffer(block, dtype=np.uint8)
		counts = np.bincount(block_arr, minlength=256)
		probs = counts / len(block_arr)

		entropy = 0.0
		for p in probs:
			if p > 0:
				entropy -= p * math.log2(p)

		e_bin = min(int(entropy), 15)
		for b in block_arr:
			bins[e_bin][b >> 4] += 1

	return bins.flatten().tolist()

# ---------------- PE EXTRACTION ----------------

def extract_pe_features(path):
	with open(path, "rb") as f:
		data = f.read()

	pe = pefile.PE(data=data, fast_load=False)

	features = {}

	# Byte-level
	features["histogram"] = byte_histogram(data)
	features["byteentropy"] = byte_entropy(data)

	# General
	features["general"] = {
		"size": len(data),
		"vsize": pe.OPTIONAL_HEADER.SizeOfImage,
		"imports": len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, "DIRECTORY_ENTRY_IMPORT") else 0,
		"exports": len(pe.DIRECTORY_ENTRY_EXPORT.symbols) if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") else 0,
		"has_debug": int(hasattr(pe, "DIRECTORY_ENTRY_DEBUG")),
		"has_resources": int(hasattr(pe, "DIRECTORY_ENTRY_RESOURCE")),
		"has_relocations": int(hasattr(pe, "DIRECTORY_ENTRY_BASERELOC")),
		"has_signature": int(pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size > 0),
		"has_tls": int(pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].Size > 0),
		"symbols": pe.FILE_HEADER.NumberOfSymbols
	}

	# Sections
	sections = []
	for s in pe.sections:
		sections.append({
			"size": s.SizeOfRawData,
			"vsize": s.Misc_VirtualSize,
			"entropy": s.get_entropy()
		})

	features["section"] = {
		"sections": sections
	}

	# Imports
	imports = {}
	if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
		for entry in pe.DIRECTORY_ENTRY_IMPORT:
			dll = entry.dll.decode(errors="ignore")
			imports[dll] = []
			for imp in entry.imports:
				if imp.name:
					imports[dll].append(imp.name.decode(errors="ignore"))

	features["imports"] = imports

	return features

# ---------------- FEATURE TRANSFORM ----------------

def transform_features(raw_features, import_vectorizer):
	vec = []

	# Byte histogram + entropy
	vec.extend(raw_features["histogram"])
	vec.extend(raw_features["byteentropy"])

	# General
	vec.extend(raw_features["general"].values())

	# Section aggregation (stable + model-friendly)
	secs = raw_features["section"]["sections"]
	if secs:
		entropies = [s["entropy"] for s in secs]
		vsizes = [s["vsize"] for s in secs]
		vec.extend([
			len(secs),
			np.mean(entropies),
			np.max(entropies),
			np.sum(vsizes)
		])
	else:
		vec.extend([0, 0, 0, 0])

	# Imports (vectorized)
	flat_imports = {}
	for dll, funcs in raw_features["imports"].items():
		flat_imports[f"dll_{dll}"] = 1
		for fn in funcs:
			flat_imports[f"api_{fn}"] = 1

	import_vec = import_vectorizer.transform([flat_imports])[0]

	return np.hstack([vec, import_vec])