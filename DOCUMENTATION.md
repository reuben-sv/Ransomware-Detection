# Ransomware Detection System - Documentation

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Project Structure](#project-structure)
4. [Modules](#modules)
5. [Analysis Pipeline](#analysis-pipeline)
6. [Datasets & Training](#datasets--training)
7. [Scoring System](#scoring-system)
8. [Setup & Usage](#setup--usage)

---

## Overview

This project is a **hybrid ransomware detection system** that combines two complementary approaches to classify Windows executables (.exe) as benign or malicious:

- **Static Analysis** - Inspects the binary file's structure (PE headers, byte patterns, imports) without executing it. Uses a trained Random Forest model for classification and SHAP values for explainability.
- **Dynamic Analysis** - Executes the file in a monitored environment and tracks runtime behavior (CPU, memory, file I/O, network activity, child processes). Uses heuristic scoring.

The final verdict is a **weighted combination** of both scores (30% static + 70% dynamic), producing a score from 0 to 100 that classifies the sample as benign, possibly malicious, or strong ransomware.

---

## Architecture

```
                          ┌──────────────┐
                          │   main.py    │
                          │ (Entry Point)│
                          └──────┬───────┘
                                 │
                 ┌───────────────┼───────────────┐
                 │               │               │
           ┌─────▼──────┐  ┌─────▼─────┐  ┌──────▼──────┐
           │  Analyze   │  │   Setup   │  │  Showcase   │
           │  (.exe)    │  │  (Models) │  │  (Demo)     │
           └─────┬──────┘  └─────┬─────┘  └──────┬──────┘
                 │               │               │
        ┌────────┴────────┐     │        static_analysis_
        │                 │     │        safe_ransomware.py
  ┌─────▼──────┐  ┌───────▼───┐│
  │  Static    │  │  Dynamic  ││   ┌─────────────────────┐
  │  Analysis  │  │  Analysis ││   │  Training Pipeline  │
  └─────┬──────┘  └───────┬───┘│   │                     │
        │                 │    ├──►│  create_*_train_set │
        │                 │    │   │  train_*_model      │
  ┌─────▼──────┐          │    │   └─────────────────────┘
  │  extract_  │          │    │
  │  static_   │          │    │
  │  features  │          │    │
  └──────┬─────┘          │    │
          │               │    │
           │     ┌────────▼────▼───┐
            ├──► │ report_generator│
                 │   (PDF output)  │
                 └─────────────────┘
```

---

## Project Structure

```
Ransomware-Detection/
│
├── main.py                          # Entry point - menu-driven interface
├── report_generator.py              # PDF report generation
├── static_analysis_safe_ransomware.py  # Safe demo on known malware features
├── requirements.txt                 # Python dependencies
│
├── analysis_modules/
│   ├── static_analysis.py           # ML-based static PE analysis
│   ├── dynamic_analysis.py          # Runtime behavior monitoring
│   └── extract_static_features.py   # PE feature extraction (pefile)
│
├── train_set_creators/
│   ├── create_static_train_set.py   # EMBER dataset → balanced CSV
│   └── create_dynamic_train_set.py  # BODMAS dataset → balanced NPZ
│
├── model_trainer/
│   ├── train_static_model.py        # Train static Random Forest
│   └── train_dynamic_model.py       # Train dynamic Random Forest
│
├── database/
│   └── malware_rows.csv             # Pre-extracted malware features for demo
│
├── models/                          # Trained models (generated at runtime)
│
└── test_executable_files/           # Sample .exe files for testing
    ├── Sample1.exe                  # Benign compiled Python script
    └── Sample2.exe                  # READEST software setup file
```

---

## Modules

### main.py

The entry point providing a menu-driven interface with three modes:

| Option | Mode     | Description                                          |
|--------|----------|------------------------------------------------------|
| 0      | Setup    | Downloads/creates training data and trains models    |
| 1      | Analyze  | Runs full analysis on a user-selected .exe file      |
| 2      | Showcase | Demonstrates detection on pre-extracted malware data |
| 3      | Exit     | Exits the program                                    |

The setup mode uses a **state machine** that tracks what's available (raw datasets, training data, trained models) and runs only the steps that are needed.

---

### analysis_modules/extract_static_features.py

Parses PE (Portable Executable) binaries using the `pefile` library and extracts raw features:

| Feature Group   | Description                                        | Dimensions |
|-----------------|----------------------------------------------------|------------|
| Byte Histogram  | Frequency of each byte value (0x00-0xFF)           | 256        |
| Byte Entropy    | Shannon entropy mapped to a 16x16 matrix           | 256        |
| General Info    | File size, virtual size, imports, exports, debug   | ~10        |
| PE Headers      | COFF timestamp, machine type, characteristics      | ~14        |
| Sections        | Name, size, entropy, virtual size (up to 10)       | ~50        |
| Imports         | DLL count, function count, specific DLL presence   | ~15        |

**How byte entropy works:**
1. A sliding window (2048 bytes, stride 1024) moves across the file
2. Shannon entropy is computed for each window
3. Entropy (0-8 bits) is mapped to a 4-bit bin, byte values to a 4-bit nibble
4. These populate a 16x16 matrix capturing the relationship between entropy levels and byte patterns

---

### analysis_modules/static_analysis.py

Loads the trained Random Forest model and classifies a file based on its static features.

**Process:**
1. Extract raw PE features using `extract_static_features.py`
2. Flatten features into a ~280-dimensional vector
3. Run through Random Forest → prediction + confidence score
4. Compute SHAP values using `TreeExplainer` to identify the top 10 features driving the decision

**Output:** `(label, confidence, top_reasons)`

---

### analysis_modules/dynamic_analysis.py

Executes the target file and monitors its runtime behavior for 8 seconds (polling every 0.2s).

**Monitored metrics:**

| Metric              | What It Captures                             |
|---------------------|----------------------------------------------|
| CPU (avg, peak)     | Processing intensity                         |
| Memory (avg, peak)  | RAM consumption                              |
| Threads (avg, peak) | Concurrency level                            |
| Open File Events    | Cumulative file access count                 |
| Child Processes     | Number of spawned subprocesses               |
| Network Events      | Active network connections                   |

**Scoring** is heuristic-based — each suspicious behavior adds +0.2 to the score (capped at 1.0).

---

### report_generator.py

Generates a PDF report containing:
- File name and path
- Visual progress bar showing the final score
- Score breakdown table (static, dynamic, final)
- Top 10 factors that influenced the verdict
- Color-coded final verdict (green = benign, red = malware)

Built with the `ReportLab` library. The report auto-opens after generation.

---

### static_analysis_safe_ransomware.py

A safe demonstration module that runs the static model on **pre-extracted** feature vectors from `malware_rows.csv` — no actual malware is executed. Uses `TreeInterpreter` to explain which features pushed the model toward a malware classification.

---

## Analysis Pipeline

When a user selects a .exe file for analysis, the following pipeline runs:

```
┌─────────────────────────────────────────────────────────┐
│                    Input: .exe file                     │
└────────────────────────┬────────────────────────────────┘
                         │
          ┌──────────────┴──────────────┐
          │                             │
    ┌─────▼──────┐              ┌───────▼───────┐
    │   STATIC   │              │    DYNAMIC    │
    │  ANALYSIS  │              │   ANALYSIS    │
    │            │              │               │
    │ 1. Parse   │              │ 1. Execute as │
    │    PE file │              │    subprocess │
    │ 2. Extract │              │ 2. Monitor    │
    │    features│              │    for 8 sec  │
    │    (~280)  │              │ 3. Collect    │
    │ 3. Predict │              │    metrics    │
    │    with RF │              │ 4. Score with │
    │ 4. SHAP    │              │    heuristics │
    │    explain │              │               │
    └─────┬──────┘              └───────┬───────┘
          │                             │
          │  Score (0-100)              │  Score (0-100)
          │  Weight: 0.3                │  Weight: 0.7
          │                             │
          └──────────┬──────────────────┘
                     │
              ┌──────▼──────┐
              │  COMBINE    │
              │             │
              │  final =    │
              │ static×0.3 +│
              │ dynamic×0.7 │
              └──────┬──────┘
                     │
              ┌──────▼──────┐
              │   VERDICT   │
              │             │
              │ ≥80: STRONG │
              │ 50-79: WEAK │
              │ <50: BENIGN │
              └──────┬──────┘
                     │
              ┌──────▼──────┐
              │  PDF REPORT │
              │ (optional)  │
              └─────────────┘
```

---

## Datasets & Training

### Datasets Used

| Dataset    | Type    | Purpose                   | Format        |
|------------|---------|---------------------------|---------------|
| EMBER 2018 | Static  | PE file feature vectors   | 6 JSONL files |
| BODMAS     | Dynamic | Runtime behavior features | NPZ archive   |

Both datasets must be downloaded separately and placed in the `database/` folder.

### Training Pipeline

**Static Model:**
1. `create_static_train_set.py` reads 6 EMBER JSONL files
2. Flattens each sample's features into ~280 columns
3. Balances to 50,000 benign + 50,000 malware = 100,000 samples
4. Saves as `database/static_training_data.csv`
5. `train_static_model.py` trains a Random Forest (300 trees, 80/20 split)
6. Saves model to `models/Static_Model.pkl`

**Dynamic Model:**
1. `create_dynamic_train_set.py` loads BODMAS `bodmas.npz`
2. Balances to 50,000 benign + 50,000 malware = 100,000 samples
3. Saves as `database/dynamic_training_data.npz`
4. `train_dynamic_model.py` trains a Random Forest (300 trees, 80/20 split)
5. Saves model to `models/Dynamic_Model.pkl`

> **Note:** The current pipeline uses heuristic scoring for dynamic analysis, not the trained dynamic model.

### Model Details

- **Algorithm:** Random Forest Classifier (scikit-learn)
- **Trees:** 300 estimators
- **Training:** Parallelized across all CPU cores (`n_jobs=-1`)
- **Split:** 80% training, 20% testing (stratified)
- **Explainability:** SHAP (TreeExplainer) for static, TreeInterpreter for showcase

---

## Scoring System

### Score Conversion

Both static and dynamic analyses produce a confidence/probability score (0.0 to 1.0), which is converted to a 0-100 scale.

### Weight Distribution

| Component | Weight | Rationale                                          |
|-----------|--------|----------------------------------------------------|
| Static    | 30%    | Structural features can be obfuscated              |
| Dynamic   | 70%    | Runtime behavior is harder to fake                 |

### Final Verdict

```
Final Score = (Static Score × 0.3) + (Dynamic Score × 0.7)
```

| Score Range | Verdict             |
|-------------|---------------------|
| >= 80       | STRONG RANSOMWARE   |
| 50 - 79     | POSSIBLE / WEAK RANSOMWARE |
| < 50        | BENIGN              |

---

## Setup & Usage

### Prerequisites

- Python 3.10+
- Conda (recommended) or pip

### Installation

```bash
# Create and activate environment
conda create -n ransomware-detection python=3.11
conda activate ransomware-detection

# Install dependencies
pip install -r requirements.txt
```

### Running the System

```bash
python main.py
```

1. **First run** — Select option `0` (Setup) to generate training data and train models
2. **Analyze files** — Select option `1`, then provide the path to an .exe file
3. **Safe demo** — Select option `2` to see the model classify known malware features

### Important Safety Note

Dynamic analysis **executes** the target file. Always run this system inside an **isolated sandbox or virtual machine** when analyzing unknown or potentially malicious files.
