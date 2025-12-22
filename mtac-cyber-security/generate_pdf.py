from weasyprint import HTML
import os

BASE = os.path.dirname(os.path.abspath(__file__))
os.makedirs(os.path.join(BASE, "static", "reports"), exist_ok=True)

HTML(os.path.join(BASE, "templates", "apa_cover.html"), base_url=BASE).write_pdf(
    os.path.join(BASE, "static", "reports", "compliance_report_nov2025.pdf")
)
print("PDF Generated: static/reports/compliance_report_nov2025.pdf")
