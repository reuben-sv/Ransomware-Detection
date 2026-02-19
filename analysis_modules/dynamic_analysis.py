import subprocess
import time
import psutil
import os
import socket
import random

# ---------------- CONFIG ----------------
MONITOR_DURATION = 8	# seconds
POLL_INTERVAL = 0.2		# seconds


# ---------------- CORE ANALYSIS ----------------
def executable_dynamic(file_path):
	start_time = time.time()

	print(f"Running executable: {file_path}")

	proc = subprocess.Popen(
		file_path,
		stdout=subprocess.DEVNULL,
		stderr=subprocess.DEVNULL,
		shell=False
	)

	ps_proc = psutil.Process(proc.pid)

	cpu_samples = []
	mem_samples = []
	thread_samples = []
	open_files_count = 0
	network_events = 0
	child_processes = set()

	while time.time() - start_time < MONITOR_DURATION:
		if not ps_proc.is_running():
			break

		try:
			cpu_samples.append(ps_proc.cpu_percent())
			mem_samples.append(ps_proc.memory_info().rss)
			thread_samples.append(ps_proc.num_threads())

			open_files_count += len(ps_proc.open_files())

			for c in ps_proc.children(recursive=True):
				child_processes.add(c.pid)

			conns = ps_proc.connections(kind="inet")
			if conns:
				network_events += len(conns)

		except (psutil.NoSuchProcess, psutil.AccessDenied):
			print("something failed")
			break

		time.sleep(POLL_INTERVAL)

	# Ensure process is terminated
	try:
		ps_proc.terminate()
	except Exception:
		pass

	# ---------------- FEATURE EXTRACTION ----------------
	features = {
		"execution_time": round(time.time() - start_time, 2),
		"cpu_avg": round(sum(cpu_samples) / max(len(cpu_samples), 1), 2),
		"cpu_peak": round(max(cpu_samples) if cpu_samples else 0, 2),
		"memory_avg": int(sum(mem_samples) / max(len(mem_samples), 1)),
		"memory_peak": int(max(mem_samples) if mem_samples else 0),
		"thread_avg": round(sum(thread_samples) / max(len(thread_samples), 1), 2),
		"thread_peak": max(thread_samples) if thread_samples else 0,
		"open_file_events": open_files_count,
		"child_process_count": len(child_processes),
		"network_events": network_events
	}

	# ---------------- SCORING (heuristic) ----------------
	score = compute_dynamic_score(features)

	return features, score


# ---------------- SCORING LOGIC ----------------
def compute_dynamic_score(f):
	score = random.uniform(0.0,0.2)

	if f["cpu_peak"] > 60:
		score += 0.2

	if f["memory_peak"] > 300 * 1024 * 1024:
		score += 0.2

	if f["child_process_count"] > 0:
		score += 0.2

	if f["network_events"] > 0:
		score += 0.2

	if f["open_file_events"] > 50:
		score += 0.2

	return min(score, 1.0)


# ---------------- PUBLIC API ----------------
def analyze_executable_dynamic(file_path):
	print("\nStarting dynamic analysis")
	features, score = executable_dynamic(file_path)

	print("\nDynamic Features:")
	for k, v in features.items():
		print(f"  {k}: {v}")

	print("\nDynamic analysis complete")

	return score