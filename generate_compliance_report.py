import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
import matplotlib.table as table
from datetime import datetime

title = "NaashonSecureIoT Compliance Report - November 2025"
output_path = "static/reports/compliance_report_nov2025.pdf"

with PdfPages(output_path) as pdf:
    # Page 1: Title
    fig1, ax1 = plt.subplots(figsize=(8.27, 11.69))
    ax1.text(0.5, 0.6, title, ha='center', va='center', fontsize=24, fontweight='bold', color='#b30000')
    ax1.text(0.5, 0.1, f"Generated: {datetime.now().strftime('%B %d, %Y %I:%M %p EAT')}", ha='center', va='center', fontsize=12)
    ax1.axis('off')
    pdf.savefig(fig1, bbox_inches='tight')
    plt.close(fig1)

    # Page 2: Compliance Checklist Table
    fig2, ax2 = plt.subplots(figsize=(8.27, 11.69))
    ax2.axis('off')
    ax2.set_title(title, fontsize=16, fontweight='bold', pad=20)
    tbl = table.table(ax2, bbox=[0, 0.2, 1, 0.6])
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(10)
    tbl.scale(1, 2)
    tbl.add_row(['Standard', 'Status', 'Audit Date', 'Notes'], colWidths=[0.3, 0.2, 0.2, 0.3])
    tbl.add_row(['GDPR', 'Compliant', 'Oct 15, 2025', 'Data protection verified'], colColours=['green'])
    tbl.add_row(['ISO 27001', 'Certified', 'Oct 15, 2025', 'ISMS audit passed'], colColours=['green'])
    tbl.add_row(['NIST CSF', 'Compliant', 'Oct 15, 2025', 'Cybersecurity framework aligned'], colColours=['green'])
    pdf.savefig(fig2, bbox_inches='tight')
    plt.close(fig2)

print(f"Enhanced PDF generated: {output_path}")
