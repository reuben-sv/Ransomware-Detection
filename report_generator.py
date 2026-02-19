from pathlib import Path
import platform
import os
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.lib import colors
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import HorizontalBarChart
from reportlab.lib import colors


def open_pdf(report_path):
	system = platform.system()
	os.startfile(report_path)

def progress_bar(percent, width=400, height=40):
	d = Drawing(width, height)
	bar = HorizontalBarChart()

	bar.x = 0
	bar.y = 5
	bar.height = 20
	bar.width = width
	bar.data = [[percent]]
	bar.valueAxis.valueMin = 0
	bar.valueAxis.valueMax = 100
	bar.barLabels.nudge = 7
	bar.barLabelFormat = '   %d%%'

	bar.bars[0].fillColor = colors.green
	d.add(bar)
	return d

def report_generator(data):
	sample_name = Path(data["file_path"]).name
	fileName = f'Analysis_Report_{sample_name}.pdf'

	doc = SimpleDocTemplate(fileName)
	story = []
	styles = getSampleStyleSheet()

	# --- Custom Styles ---
	title_style = ParagraphStyle(
		'name="Title"',
		parent=styles['Title'],
		alignment=TA_CENTER,
		fontSize=26,
		spaceAfter=20
	)

	section_style = ParagraphStyle(
		'name="Section"',
		parent=styles['Heading2'],
		textColor=colors.darkblue,
		spaceAfter=10
	)

	normal_style = styles['Normal']

	verdict_color = colors.green if data["verdict"] == "BENIGN" else colors.red
	verdict_style = ParagraphStyle(
		'name="Verdict"',
		parent=styles['Heading1'],
		textColor=verdict_color,
		alignment=TA_CENTER,
		spaceBefore=20,
		spaceAfter=20
	)

	# --- Title ---
	title = f'Analysis Report of {sample_name}'
	story.append(Paragraph(title, title_style))
	story.append(Spacer(1, 20))

	# --- File Info ---
	story.append(Paragraph("File Location", section_style))
	story.append(Paragraph(f"{data['file_path']}", normal_style))
	story.append(Spacer(1, 20))

	# --- Scores Table ---
	story.append(Paragraph("Detection Scores", section_style))
	story.append(progress_bar(data["final_score"]))
	story.append(Paragraph("\n", section_style))
	score_data = [
		["Final Score", data["final_score"]],
		["Static Score", data["static_score"]],
		["Dynamic Score", data["dynamic_score"]],
	]

	table = Table(score_data, colWidths=[200, 100])
	table.setStyle(TableStyle([
		('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
		('GRID', (0,0), (-1,-1), 1, colors.black),
		('FONTNAME', (0,0), (-1,-1), 'Courier'),
		('ALIGN', (1,0), (1,-1), 'CENTER')
	]))
	story.append(table)
	story.append(Spacer(1, 25))

	# --- Static Reasons ---
	story.append(Paragraph("Top Factors Affecting Verdict", section_style))
	for reason in data["static_reasons"]:
		story.append(Paragraph(f"• {reason}", normal_style))
	story.append(Spacer(1, 25))

	# --- Verdict ---
	story.append(Paragraph(f"FINAL VERDICT: {data['verdict']}", verdict_style))

	doc.build(story)
	print(f"Report saved as {fileName}")
	open_pdf(fileName)



if __name__ == "__main__":
	# This is for testing only
	data = {
		"file_path": r"C:\Projects\Ransomware-Detection\test_executable_files\Sample2.exe",
		"static_reasons": [
			"header_optional_subsystem -0.0176 (Benign Likelihood Increased)",
			"header_coff_machine -0.0136 (Benign Likelihood Increased)",
			"header_optional_magic -0.0134 (Benign Likelihood Increased)",
			"entropy_254 -0.0085 (Benign Likelihood Increased)",
			"entropy_255 -0.0077 (Benign Likelihood Increased)",
			"general_has_debug -0.0076 (Benign Likelihood Increased)",
			"entropy_244 -0.0071 (Benign Likelihood Increased)",
			"entropy_118 -0.0067 (Benign Likelihood Increased)",
			"entropy_251 -0.0055 (Benign Likelihood Increased)",
			"entropy_252 -0.0051 (Benign Likelihood Increased)"
		],
		"static_score": 52,
		"dynamic_score": 7,
		"final_score": 15,
		"verdict": "BENIGN"
	}

	report_generator(data)