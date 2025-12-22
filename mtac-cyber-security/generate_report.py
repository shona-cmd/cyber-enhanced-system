import os
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
from datetime import datetime

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
REPORT_TITLE = "NaashonSecureIoT Compliance Report - November 2025"
OUTPUT_DIR = "static/reports"
OUTPUT_PATH = os.path.join(OUTPUT_DIR, "compliance_report_nov2025.pdf")

# Ensure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

# --------------------------------------------------------------------------- #
# Generate PDF
# --------------------------------------------------------------------------- #
with PdfPages(OUTPUT_PATH) as pdf:
    fig, ax = plt.subplots(figsize=(8.27, 11.69))  # A4 size in inches
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)

    # Title
    ax.text(
        0.5, 0.6,
        REPORT_TITLE,
        ha='center', va='center',
        fontsize=24, fontweight='bold',
        color='#b30000'  # UCOL red
    )

    # Generated date
    generated_date = datetime.now().strftime("%B %d, %Y %I:%M %p EAT")
    ax.text(
        0.5, 0.1,
        f"Generated: {generated_date}",
        ha='center', va='center',
        fontsize=12, style='italic'
    )

    # Footer (UCOL style)
    ax.text(
        0.5, 0.05,
        "NaashonSecureIoT • MTAC Edge/Cloud Node • Kampala, Uganda",
        ha='center', va='center',
        fontsize=10, color='gray'
    )

    ax.axis('off')
    pdf.savefig(fig, bbox_inches='tight', pad_inches=0.5)
    plt.close(fig)

print(f"PDF generated successfully: {OUTPUT_PATH}")
