timport matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
import datetime

# Content from temp.txt
title = "NaashonSecureIoT Compliance Report - November 2025"

# Create PDF
with PdfPages('compliance_report_nov2025.pdf') as pdf:
    fig, ax = plt.subplots(figsize=(8.27, 11.69))  # A4 size
    ax.text(0.5, 0.5, title, ha='center', va='center', fontsize=24, fontweight='bold')
    ax.text(0.5, 0.1, f"Generated: {datetime.date.today()}", ha='center', va='center', fontsize=12)
    ax.axis('off')
    pdf.savefig(fig, bbox_inches='tight')
    plt.close()
print("PDF generated: compliance_report_nov2025.pdf")
