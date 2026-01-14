# =========================
# RAW FEATURE EXTRACTION
# =========================
import pefile
import numpy as np
import json
import math
from pathlib import Path

# ---------------- CONFIG ----------------
INPUT_FILE = "test_executable_files\\benign_demo.exe"

# ---------------- BYTE FEATURES ----------------
def byte_histogram(data):
    """Calculate histogram of byte values (256 bins)"""
    hist = np.zeros(256, dtype=int)
    for b in data:
        hist[b] += 1
    return hist.tolist()

def byte_entropy(data, window=2048, step=1024):
    """Calculate byte entropy in sliding windows"""
    bins = np.zeros((16, 16), dtype=int)
    for i in range(0, len(data) - window, step):
        block = data[i:i + window]
        if not block:
            continue
        
        entropy = 0.0
        counts = np.bincount(block, minlength=256)
        probs = counts / len(block)
        for p in probs:
            if p > 0:
                entropy -= p * math.log2(p)
        
        e_bin = min(int(entropy), 15)
        for b in block:
            bins[e_bin][b >> 4] += 1
    
    return bins.flatten().tolist()

# ---------------- PE FEATURES ----------------
def extract_pe_features(path):
    """Extract PE features in EMBER format"""
    
    # Read file
    with open(path, "rb") as f:
        data = f.read()
    
    # Parse PE
    pe = pefile.PE(data=data, fast_load=False)
    
    features = {}
    
    # 1. Histogram
    features["histogram"] = byte_histogram(data)
    
    # 2. Byte Entropy
    features["byteentropy"] = byte_entropy(data)
    
    # 3. General features
    features["general"] = {
        "size": len(data),
        "vsize": pe.OPTIONAL_HEADER.SizeOfImage,
        "has_debug": int(hasattr(pe, "DIRECTORY_ENTRY_DEBUG")),
        "exports": len(pe.DIRECTORY_ENTRY_EXPORT.symbols) if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") else 0,
        "imports": len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, "DIRECTORY_ENTRY_IMPORT") else 0,
        "has_relocations": int(hasattr(pe, "DIRECTORY_ENTRY_BASERELOC")),
        "has_resources": int(hasattr(pe, "DIRECTORY_ENTRY_RESOURCE")),
        "has_signature": int(len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 4 and pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size > 0),
        "has_tls": int(len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 9 and pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].Size > 0),
        "symbols": pe.FILE_HEADER.NumberOfSymbols
    }
    
    # 4. Header features
    # COFF characteristics
    coff_characteristics = []
    char_flags = {
        0x0001: "RELOCS_STRIPPED",
        0x0002: "EXECUTABLE_IMAGE",
        0x0004: "LINE_NUMS_STRIPPED",
        0x0008: "LOCAL_SYMS_STRIPPED",
        0x0020: "LARGE_ADDRESS_AWARE",
        0x0100: "CHARA_32BIT_MACHINE",
        0x0200: "DEBUG_STRIPPED",
        0x1000: "SYSTEM",
        0x2000: "DLL"
    }
    for flag, name in char_flags.items():
        if pe.FILE_HEADER.Characteristics & flag:
            coff_characteristics.append(name)
    
    # Optional header DLL characteristics
    dll_characteristics = []
    dll_flags = {
        0x0040: "DYNAMIC_BASE",
        0x0080: "FORCE_INTEGRITY",
        0x0100: "NX_COMPAT",
        0x0200: "NO_ISOLATION",
        0x0400: "NO_SEH",
        0x0800: "NO_BIND",
        0x2000: "WDM_DRIVER",
        0x8000: "TERMINAL_SERVER_AWARE"
    }
    for flag, name in dll_flags.items():
        if pe.OPTIONAL_HEADER.DllCharacteristics & flag:
            dll_characteristics.append(name)
    
    # Machine type
    machine_types = {332: "I386", 34404: "AMD64", 452: "ARM"}
    machine = machine_types.get(pe.FILE_HEADER.Machine, "UNKNOWN")
    
    # Subsystem
    subsystem_types = {
        1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI",
        5: "OS2_CUI", 7: "POSIX_CUI", 9: "WINDOWS_CE_GUI"
    }
    subsystem = subsystem_types.get(pe.OPTIONAL_HEADER.Subsystem, "UNKNOWN")
    
    # Magic
    magic_types = {267: "PE32", 523: "PE32+"}
    magic = magic_types.get(pe.OPTIONAL_HEADER.Magic, "UNKNOWN")
    
    features["header"] = {
        "coff": {
            "timestamp": pe.FILE_HEADER.TimeDateStamp,
            "machine": machine,
            "characteristics": coff_characteristics
        },
        "optional": {
            "subsystem": subsystem,
            "dll_characteristics": dll_characteristics,
            "magic": magic,
            "major_image_version": pe.OPTIONAL_HEADER.MajorImageVersion,
            "minor_image_version": pe.OPTIONAL_HEADER.MinorImageVersion,
            "major_linker_version": pe.OPTIONAL_HEADER.MajorLinkerVersion,
            "minor_linker_version": pe.OPTIONAL_HEADER.MinorLinkerVersion,
            "major_operating_system_version": pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
            "minor_operating_system_version": pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
            "major_subsystem_version": pe.OPTIONAL_HEADER.MajorSubsystemVersion,
            "minor_subsystem_version": pe.OPTIONAL_HEADER.MinorSubsystemVersion,
            "sizeof_code": pe.OPTIONAL_HEADER.SizeOfCode,
            "sizeof_headers": pe.OPTIONAL_HEADER.SizeOfHeaders,
            "sizeof_heap_commit": pe.OPTIONAL_HEADER.SizeOfHeapCommit
        }
    }
    
    # 5. Section features
    sections = []
    for s in pe.sections:
        # Section properties
        props = []
        if s.Characteristics & 0x00000020:
            props.append("CNT_CODE")
        if s.Characteristics & 0x00000040:
            props.append("CNT_INITIALIZED_DATA")
        if s.Characteristics & 0x00000080:
            props.append("CNT_UNINITIALIZED_DATA")
        if s.Characteristics & 0x20000000:
            props.append("MEM_EXECUTE")
        if s.Characteristics & 0x40000000:
            props.append("MEM_READ")
        if s.Characteristics & 0x80000000:
            props.append("MEM_WRITE")
        
        sections.append({
            "name": s.Name.decode(errors="ignore").strip("\x00"),
            "size": s.SizeOfRawData,
            "entropy": s.get_entropy(),
            "vsize": s.Misc_VirtualSize,
            "props": props
        })
    
    features["section"] = {
        "entry": sections[0]["name"] if sections else "",
        "sections": sections
    }
    
    # 6. Imports
    imports = {}
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode(errors="ignore") if entry.dll else "unknown"
            imports[dll] = []
            for imp in entry.imports:
                if imp.name:
                    imports[dll].append(imp.name.decode(errors="ignore"))
    
    features["imports"] = imports
    
    # 7. Exports (empty for most EXEs)
    features["exports"] = []
    
    # 8. Data directories (optional, for completeness)
    datadirs = []
    dir_names = [
        "EXPORT_TABLE", "IMPORT_TABLE", "RESOURCE_TABLE", "EXCEPTION_TABLE",
        "CERTIFICATE_TABLE", "BASE_RELOCATION_TABLE", "DEBUG", "ARCHITECTURE",
        "GLOBAL_PTR", "TLS_TABLE", "LOAD_CONFIG_TABLE", "BOUND_IMPORT",
        "IAT", "DELAY_IMPORT_DESCRIPTOR", "CLR_RUNTIME_HEADER"
    ]
    for i, name in enumerate(dir_names):
        if i < len(pe.OPTIONAL_HEADER.DATA_DIRECTORY):
            dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[i]
            datadirs.append({
                "name": name,
                "size": dd.Size,
                "virtual_address": dd.VirtualAddress
            })
    features["datadirectories"] = datadirs
    
    return features

# ---------------- FLATTEN FOR CSV ----------------
def flatten_for_csv(features):
    """Flatten extracted features into a single row for CSV/ML model"""
    row = {}
    
    # 1. Histogram (256 features)
    histogram = features.get('histogram', [0] * 256)
    for i, val in enumerate(histogram):
        row[f'hist_{i}'] = val
    
    # 2. Byte Entropy (256 features)
    byteentropy = features.get('byteentropy', [0] * 256)
    for i, val in enumerate(byteentropy):
        row[f'entropy_{i}'] = val
    
    # 3. General features
    general = features.get('general', {})
    row['general_size'] = general.get('size', 0)
    row['general_vsize'] = general.get('vsize', 0)
    row['general_has_debug'] = general.get('has_debug', 0)
    row['general_exports'] = general.get('exports', 0)
    row['general_imports'] = general.get('imports', 0)
    row['general_has_relocations'] = general.get('has_relocations', 0)
    row['general_has_resources'] = general.get('has_resources', 0)
    row['general_has_signature'] = general.get('has_signature', 0)
    row['general_has_tls'] = general.get('has_tls', 0)
    row['general_symbols'] = general.get('symbols', 0)
    
    # 4. Header features
    header = features.get('header', {})
    coff = header.get('coff', {})
    row['header_coff_timestamp'] = coff.get('timestamp', 0)
    row['header_coff_machine'] = 1 if coff.get('machine') == 'I386' else 0
    row['header_coff_characteristics_count'] = len(coff.get('characteristics', []))
    
    optional = header.get('optional', {})
    row['header_optional_subsystem'] = 1 if optional.get('subsystem') == 'WINDOWS_GUI' else 0
    row['header_optional_dll_characteristics_count'] = len(optional.get('dll_characteristics', []))
    row['header_optional_magic'] = 1 if optional.get('magic') == 'PE32' else 2 if optional.get('magic') == 'PE32+' else 0
    row['header_optional_major_linker_version'] = optional.get('major_linker_version', 0)
    row['header_optional_minor_linker_version'] = optional.get('minor_linker_version', 0)
    row['header_optional_major_image_version'] = optional.get('major_image_version', 0)
    row['header_optional_minor_image_version'] = optional.get('minor_image_version', 0)
    row['header_optional_major_os_version'] = optional.get('major_operating_system_version', 0)
    row['header_optional_minor_os_version'] = optional.get('minor_operating_system_version', 0)
    row['header_optional_sizeof_code'] = optional.get('sizeof_code', 0)
    row['header_optional_sizeof_headers'] = optional.get('sizeof_headers', 0)
    row['header_optional_sizeof_heap_commit'] = optional.get('sizeof_heap_commit', 0)
    
    # 5. Section features
    section = features.get('section', {})
    sections = section.get('sections', [])
    row['section_count'] = len(sections)
    row['section_entry'] = 1 if section.get('entry') == '.text' else 0
    
    for i in range(10):
        if i < len(sections):
            s = sections[i]
            row[f'section_{i}_size'] = s.get('size', 0)
            row[f'section_{i}_entropy'] = s.get('entropy', 0)
            row[f'section_{i}_vsize'] = s.get('vsize', 0)
            row[f'section_{i}_props_count'] = len(s.get('props', []))
        else:
            row[f'section_{i}_size'] = 0
            row[f'section_{i}_entropy'] = 0
            row[f'section_{i}_vsize'] = 0
            row[f'section_{i}_props_count'] = 0
    
    # 6. Imports features
    imports = features.get('imports', {})
    total_imported_functions = sum(len(funcs) for funcs in imports.values())
    row['imports_dll_count'] = len(imports)
    row['imports_function_count'] = total_imported_functions
    
    common_dlls = ['KERNEL32.dll', 'USER32.dll', 'GDI32.dll', 'ADVAPI32.dll', 
                   'SHELL32.dll', 'ole32.dll', 'COMCTL32.dll', 'WININET.dll',
                   'WS2_32.dll', 'ntdll.dll']
    
    for dll in common_dlls:
        row[f'imports_has_{dll.replace(".", "_").lower()}'] = 1 if dll in imports else 0
    
    for dll in ['KERNEL32.dll', 'USER32.dll', 'ADVAPI32.dll']:
        row[f'imports_{dll.replace(".", "_").lower()}_count'] = len(imports.get(dll, []))
    
    return row

# ---------------- MAIN (for testing) ----------------
if __name__ == "__main__":
    print(f"Extracting features from: {INPUT_FILE}")
    
    features = extract_pe_features(INPUT_FILE)
    
    # Print as JSON
    print(json.dumps(features, indent=2))
    
    # Also show flattened version info
    flattened = flatten_for_csv(features)
    print(f"\nTotal flattened features: {len(flattened)}")
def extract_pe_features(path):	# MAIN FUNCTION
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

# =========================
# BYTE FEATURES
# =========================

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

# =========================
# FEATURE TRANSFORMER
# =========================

def transform_features(raw_features, import_vectorizer):
	vec = []

	# Histogram + entropy
	vec.extend(raw_features["histogram"])
	vec.extend(raw_features["byteentropy"])

	# General
	vec.extend(raw_features["general"].values())

	# Section aggregation (MATCH TRAINING)
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

# =========================
# TEST
# =========================

if __name__ == "__main__":
	features = extract_pe_features(INPUT_FILE)
	print(json.dumps(features, indent=2))
