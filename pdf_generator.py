import os
import time
from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, PageBreak
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to dynamically compute total pages and add 
    header, footer, and 'Page X of Y' numbering to every page.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_elements(num_pages)
            super().showPage()
        super().save()

    def draw_page_elements(self, page_count):
        self.saveState()
        
        # Suppress headers/footers on page 1 (Cover Page)
        if self._pageNumber == 1:
            self.restoreState()
            return

        # Colors
        primary_color = colors.HexColor("#1A365D")  # Deep Navy
        border_color = colors.HexColor("#E2E8F0")   # Light Gray
        text_color = colors.HexColor("#718096")     # Charcoal Gray

        # --- Header ---
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(primary_color)
        self.drawString(54, 750, "AI-POWERED DAST SECURITY REPORT")
        self.setFont("Helvetica", 8)
        self.setFillColor(text_color)
        self.drawRightString(558, 750, "CONFIDENTIAL")
        
        # Header line
        self.setStrokeColor(border_color)
        self.setLineWidth(0.5)
        self.line(54, 742, 558, 742)

        # --- Footer ---
        # Footer line
        self.line(54, 60, 558, 60)
        
        # Footer text
        self.drawString(54, 45, "Generated automatically by AI DAST Agent Orchestrator")
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(558, 45, page_text)
        
        self.restoreState()


def get_severity_color(severity):
    severity = str(severity).lower()
    if "critical" in severity:
        return colors.HexColor("#742A2A")  # Dark Red
    elif "high" in severity:
        return colors.HexColor("#C53030")  # Red
    elif "medium" in severity:
        return colors.HexColor("#DD6B20")  # Orange
    elif "low" in severity:
        return colors.HexColor("#3182CE")  # Blue
    else:
        return colors.HexColor("#4A5568")  # Charcoal for Informational


def generate_pdf_report(report_data, output_filepath, is_executive=True):
    """
    Generates a PDF report using ReportLab.
    report_data is a dict containing target info, stats, and lists of findings.
    is_executive determines if it generates the Executive or Technical report.
    """
    doc = SimpleDocTemplate(
        output_filepath,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=72,
        bottomMargin=72
    )

    styles = getSampleStyleSheet()
    
    # Custom styles
    primary = colors.HexColor("#1A365D")    # Deep Navy
    secondary = colors.HexColor("#2B6CB0")  # Slate Blue
    dark_gray = colors.HexColor("#2D3748")  # Charcoal
    light_bg = colors.HexColor("#F7FAFC")   # Off-white

    title_style = ParagraphStyle(
        'CoverTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=32,
        leading=38,
        textColor=primary,
        spaceAfter=15
    )
    
    subtitle_style = ParagraphStyle(
        'CoverSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=14,
        leading=18,
        textColor=secondary,
        spaceAfter=30
    )

    h1_style = ParagraphStyle(
        'H1',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=primary,
        spaceBefore=15,
        spaceAfter=10,
        keepWithNext=True
    )

    h2_style = ParagraphStyle(
        'H2',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=secondary,
        spaceBefore=12,
        spaceAfter=8,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'Body',
        parent=styles['BodyText'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=dark_gray,
        spaceAfter=8
    )

    bold_body_style = ParagraphStyle(
        'BoldBody',
        parent=body_style,
        fontName='Helvetica-Bold'
    )

    bullet_style = ParagraphStyle(
        'Bullet',
        parent=body_style,
        leftIndent=15,
        firstLineIndent=-10,
        spaceAfter=4
    )

    meta_label_style = ParagraphStyle(
        'MetaLabel',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=12,
        textColor=primary
    )

    meta_val_style = ParagraphStyle(
        'MetaValue',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=12,
        textColor=dark_gray
    )

    finding_title_style = ParagraphStyle(
        'FindingTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=15,
        textColor=colors.white
    )

    story = []

    # ==================== PAGE 1: COVER PAGE ====================
    story.append(Spacer(1, 120))
    report_title = "EXECUTIVE SECURITY REPORT" if is_executive else "TECHNICAL SECURITY REPORT"
    story.append(Paragraph(report_title, title_style))
    story.append(Paragraph("AI-Powered Dynamic Application Security Testing (DAST)", subtitle_style))
    
    # Visual divider
    divider_table = Table([[""]], colWidths=[504])
    divider_table.setStyle(TableStyle([
        ('LINEBELOW', (0, 0), (-1, -1), 4, primary),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
        ('TOPPADDING', (0, 0), (-1, -1), 0),
    ]))
    story.append(divider_table)
    story.append(Spacer(1, 40))

    # Metadata Block
    target_url = report_data.get("target_url", "N/A")
    scan_date = report_data.get("scan_date", time.strftime("%Y-%m-%d %H:%M:%S UTC"))
    risk_score = report_data.get("risk_score", "N/A")
    frameworks = ", ".join(report_data.get("frameworks", ["Generic Web App"]))

    meta_data = [
        [Paragraph("Target URL:", meta_label_style), Paragraph(target_url, meta_val_style)],
        [Paragraph("Scan Date/Time:", meta_label_style), Paragraph(scan_date, meta_val_style)],
        [Paragraph("Frameworks:", meta_label_style), Paragraph(frameworks, meta_val_style)],
        [Paragraph("Risk Score:", meta_label_style), Paragraph(f"<b>{risk_score}/100</b>", meta_val_style)],
    ]
    
    meta_table = Table(meta_data, colWidths=[120, 384])
    meta_table.setStyle(TableStyle([
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('LINEBELOW', (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
    ]))
    story.append(meta_table)
    
    story.append(Spacer(1, 100))
    story.append(Paragraph("<b>CONFIDENTIALITY NOTICE:</b> The information contained in this report is highly sensitive. It exposes security attributes of the target application and should be shared strictly on a need-to-know basis.", body_style))
    story.append(PageBreak())

    # ==================== PAGE 2: EXEC SUMMARY & STATS ====================
    story.append(Paragraph("Executive Summary", h1_style))
    exec_summary_text = report_data.get("executive_summary", "This report contains security assessment results compiled by the AI DAST orchestration agent. High and Critical vulnerabilities have been verified using AI to minimize false positives.")
    story.append(Paragraph(exec_summary_text, body_style))
    story.append(Spacer(1, 15))

    # Stats Table
    stats = report_data.get("stats", {})
    stats_data = [
        [
            Paragraph("<b>Severity</b>", meta_label_style), 
            Paragraph("<b>Count</b>", meta_label_style), 
            Paragraph("<b>AI Validated</b>", meta_label_style)
        ],
        [Paragraph("Critical", bold_body_style), Paragraph(str(stats.get("critical", 0)), body_style), Paragraph(str(stats.get("critical_validated", 0)), body_style)],
        [Paragraph("High", bold_body_style), Paragraph(str(stats.get("high", 0)), body_style), Paragraph(str(stats.get("high_validated", 0)), body_style)],
        [Paragraph("Medium", bold_body_style), Paragraph(str(stats.get("medium", 0)), body_style), Paragraph("Direct/ZAP", body_style)],
        [Paragraph("Low", bold_body_style), Paragraph(str(stats.get("low", 0)), body_style), Paragraph("Direct/ZAP", body_style)],
        [Paragraph("Informational", bold_body_style), Paragraph(str(stats.get("informational", 0)), body_style), Paragraph("Direct/ZAP", body_style)]
    ]
    
    stats_table = Table(stats_data, colWidths=[150, 150, 204])
    stats_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), light_bg),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E0")),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, light_bg]),
    ]))
    story.append(stats_table)
    story.append(Spacer(1, 20))

    if is_executive:
        story.append(Paragraph("Business & Operational Impact", h2_style))
        business_impact = report_data.get("business_impact", "Security vulnerabilities expose client data, core applications, and service continuity. Unaddressed issues can result in financial loss, regulatory fines, and reputational damage. Remediation of identified items should be prioritized immediately based on the provided schedule.")
        story.append(Paragraph(business_impact, body_style))
        story.append(Spacer(1, 15))

        story.append(Paragraph("Strategic Recommendations", h2_style))
        recs = report_data.get("strategic_recommendations", [])
        if not recs:
            recs = [
                "Remediate Critical SQL Injection vulnerability to prevent database compromise.",
                "Ensure all form interactions enforce robust CSRF protection mechanisms.",
                "Implement solid HTTP Security headers across all application endpoints."
            ]
        for rec in recs:
            story.append(Paragraph(f"• {rec}", bullet_style))
            
    else:
        # Technical Report - Detail all pages crawled and forms found
        story.append(Paragraph("Reconnaissance Details", h2_style))
        story.append(Paragraph(f"<b>Pages Crawled:</b> {report_data.get('pages_crawled_count', 0)}", body_style))
        story.append(Paragraph(f"<b>Forms Found:</b> {report_data.get('forms_found_count', 0)}", body_style))
        
        frameworks_list = report_data.get("frameworks", [])
        story.append(Paragraph("<b>Detected Technologies:</b>", bold_body_style))
        for f in frameworks_list:
            story.append(Paragraph(f"• {f}", bullet_style))

    story.append(PageBreak())

    # ==================== PAGE 3+: FINDINGS DETAILS ====================
    findings = report_data.get("findings", [])
    
    if is_executive:
        # Executive report only displays High/Critical validated findings
        display_findings = [f for f in findings if str(f.get("risk", "")).lower() in ["critical", "high"]]
        story.append(Paragraph("Validated High & Critical Vulnerabilities", h1_style))
        if not display_findings:
            story.append(Paragraph("No High or Critical vulnerabilities were identified during this scan.", body_style))
    else:
        # Technical report displays everything, including validation details for High/Critical
        display_findings = findings
        story.append(Paragraph("Detailed Security Findings List", h1_style))

    for idx, finding in enumerate(display_findings, 1):
        severity = finding.get("risk", "Low")
        sev_color = get_severity_color(severity)
        
        # Header block for the finding
        header_text = f"{idx}. [{severity.upper()}] {finding.get('alert', 'Vulnerability')}"
        title_p = Paragraph(header_text, finding_title_style)
        
        header_table = Table([[title_p]], colWidths=[504])
        header_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), sev_color),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('LEFTPADDING', (0,0), (-1,-1), 10),
        ]))

        # Finding details rows
        detail_rows = []
        detail_rows.append([Paragraph("<b>URL:</b>", meta_label_style), Paragraph(finding.get("url", "N/A"), meta_val_style)])
        
        if finding.get("parameter"):
            detail_rows.append([Paragraph("<b>Parameter:</b>", meta_label_style), Paragraph(finding.get("parameter", ""), meta_val_style)])
            
        detail_rows.append([Paragraph("<b>Description:</b>", meta_label_style), Paragraph(finding.get("description", ""), meta_val_style)])
        detail_rows.append([Paragraph("<b>Remediation:</b>", meta_label_style), Paragraph(finding.get("solution", ""), meta_val_style)])
        
        if finding.get("evidence"):
            detail_rows.append([Paragraph("<b>Evidence:</b>", meta_label_style), Paragraph(f"<font face='Courier' size='8'>{finding.get('evidence', '')}</font>", meta_val_style)])

        # AI Enrichment fields
        if "ai_confidence" in finding:
            conf_color = "#38A169" if float(finding.get("ai_confidence", 0.0)) >= 0.7 else "#DD6B20"
            conf_str = f"<font color='{conf_color}'><b>{int(finding.get('ai_confidence', 0.0)*100)}%</b></font>"
            detail_rows.append([Paragraph("<b>AI Confidence:</b>", meta_label_style), Paragraph(conf_str, meta_val_style)])
            
        if "ai_reasoning" in finding:
            detail_rows.append([Paragraph("<b>AI Analysis:</b>", meta_label_style), Paragraph(finding.get("ai_reasoning", ""), meta_val_style)])

        if not is_executive:
            # Show CWE / WASC metadata in Technical Report
            meta_links = []
            if finding.get("cweid"):
                meta_links.append(f"CWE-{finding.get('cweid')}")
            if finding.get("wascid"):
                meta_links.append(f"WASC-{finding.get('wascid')}")
            if meta_links:
                detail_rows.append([Paragraph("<b>Reference:</b>", meta_label_style), Paragraph(", ".join(meta_links), meta_val_style)])

        details_table = Table(detail_rows, colWidths=[100, 404])
        details_table.setStyle(TableStyle([
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('BACKGROUND', (0,0), (-1,-1), light_bg),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('LEFTPADDING', (0,0), (-1,-1), 10),
            ('RIGHTPADDING', (0,0), (-1,-1), 10),
            ('LINEBELOW', (0,0), (-1,-2), 0.5, colors.HexColor("#E2E8F0")),
        ]))

        # Wrap in KeepTogether to avoid awkward page breaks within a finding
        story.append(KeepTogether([
            header_table,
            details_table,
            Spacer(1, 15)
        ]))

    # Build the document
    doc.build(story, canvasmaker=NumberedCanvas)
