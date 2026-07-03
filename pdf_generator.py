import os
import time
from xml.sax.saxutils import escape as _xml_escape
from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, PageBreak, Image
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


def create_severity_chart(stats, output_path="findings_severity_chart.png"):
    """
    Renders a severity-breakdown bar chart PNG from the report stats dict.
    Uses the non-interactive 'Agg' backend so it is safe to run headless and
    off the main thread (e.g. inside the Flask pipeline worker).
    Returns the output path.
    """
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    severities = ["Critical", "High", "Medium", "Low", "Info"]
    counts = [
        stats.get("critical", 0),
        stats.get("high", 0),
        stats.get("medium", 0),
        stats.get("low", 0),
        stats.get("informational", 0)
    ]
    colors_list = ["#742A2A", "#C53030", "#DD6B20", "#3182CE", "#4A5568"]

    plt.figure(figsize=(6, 3))
    bars = plt.bar(severities, counts, color=colors_list)
    plt.title("Vulnerabilities by Severity Level")
    plt.ylabel("Number of Findings")
    plt.grid(axis='y', linestyle='--', alpha=0.5)

    # Annotate each bar with its count for at-a-glance reading.
    for bar, count in zip(bars, counts):
        plt.text(bar.get_x() + bar.get_width() / 2, bar.get_height(),
                 str(count), ha='center', va='bottom', fontsize=9)

    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()
    return output_path


def esc(value):
    """
    Escape dynamic/untrusted text before it is placed inside a reportlab
    Paragraph. ZAP alert fields (evidence, description, HTTP req/res) and
    scraped page content routinely contain real HTML, e.g.
    <a href="#" class="...">. Reportlab's mini-HTML paragraph parser would
    otherwise try to interpret that markup and crash on unsupported
    attributes (class, div, img, ...). Escaping renders it as literal text.
    """
    if value is None:
        return ""
    return _xml_escape(str(value))


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
        [Paragraph("Target URL:", meta_label_style), Paragraph(esc(target_url), meta_val_style)],
        [Paragraph("Scan Date/Time:", meta_label_style), Paragraph(esc(scan_date), meta_val_style)],
        [Paragraph("Frameworks:", meta_label_style), Paragraph(esc(frameworks), meta_val_style)],
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
    exec_summary_text = report_data.get("executive_summary", "")
    story.append(Paragraph(esc(exec_summary_text), body_style))
    story.append(Spacer(1, 15))

    # Stats Table
    stats = report_data.get("stats", {})
    ai_used = report_data.get("ai_used", False)
    
    stats_data = [
        [
            Paragraph("<b>Severity</b>", meta_label_style), 
            Paragraph("<b>Count</b>", meta_label_style), 
            Paragraph("<b>AI Status</b>" if ai_used else "<b>Scan Status</b>", meta_label_style)
        ],
        [Paragraph("Critical", bold_body_style), Paragraph(str(stats.get("critical", 0)), body_style), Paragraph(str(stats.get("critical_validated", 0)) + " Validated" if ai_used else "Active", body_style)],
        [Paragraph("High", bold_body_style), Paragraph(str(stats.get("high", 0)), body_style), Paragraph(str(stats.get("high_validated", 0)) + " Validated" if ai_used else "Active", body_style)],
        [Paragraph("Medium", bold_body_style), Paragraph(str(stats.get("medium", 0)), body_style), Paragraph("Direct Scan alert", body_style)],
        [Paragraph("Low", bold_body_style), Paragraph(str(stats.get("low", 0)), body_style), Paragraph("Direct Scan alert", body_style)],
        [Paragraph("Informational", bold_body_style), Paragraph(str(stats.get("informational", 0)), body_style), Paragraph("Direct Scan alert", body_style)]
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
    story.append(Spacer(1, 15))

    # Severity distribution chart (satisfies the "Charts/graphs" report requirement).
    try:
        chart_path = create_severity_chart(stats)
        if os.path.exists(chart_path):
            story.append(Paragraph("Severity Distribution", h2_style))
            story.append(Image(chart_path, width=360, height=180))
    except Exception:
        # Charts are a visual enhancement; never let a plotting failure break the report.
        pass
    story.append(Spacer(1, 20))

    if is_executive:
        story.append(Paragraph("Business & Operational Impact", h2_style))
        business_impact = report_data.get("business_impact", "")
        story.append(Paragraph(esc(business_impact), body_style))
        story.append(Spacer(1, 15))

        story.append(Paragraph("Strategic Recommendations", h2_style))
        recs = report_data.get("strategic_recommendations", [])
        for rec in recs:
            story.append(Paragraph(f"• {esc(rec)}", bullet_style))
            
    else:
        # Technical Report - Detail all pages crawled and forms found
        story.append(Paragraph("Reconnaissance Details", h2_style))
        story.append(Paragraph(f"<b>Pages Crawled:</b> {report_data.get('pages_crawled_count', 0)}", body_style))
        story.append(Paragraph(f"<b>Forms Found:</b> {report_data.get('forms_found_count', 0)}", body_style))
        
        frameworks_list = report_data.get("frameworks", [])
        story.append(Paragraph("<b>Detected Technologies:</b>", bold_body_style))
        for f in frameworks_list:
            story.append(Paragraph(f"• {esc(f)}", bullet_style))

    story.append(PageBreak())

    # ==================== PAGE 3+: FINDINGS DETAILS ====================
    findings = report_data.get("findings", [])
    info_findings = []
    if is_executive:
        # Include all High/Critical findings (skipping duplicate URL instances to avoid redundancy).
        display_findings = [f for f in findings if str(f.get("risk", "")).lower() in ["critical", "high"] and not f.get("is_duplicate", False)]
        story.append(Paragraph("High & Critical Vulnerabilities Summary", h1_style))
        if not display_findings:
            story.append(Paragraph("No High or Critical vulnerabilities were identified.", body_style))
    else:
        # Technical report details actionable findings individually, but collapses
        # the (often huge) volume of Informational passive findings into a summary
        # table so the PDF stays a manageable size.
        display_findings = [f for f in findings if "info" not in str(f.get("risk", "")).lower() and not f.get("is_duplicate", False)]
        info_findings = [f for f in findings if "info" in str(f.get("risk", "")).lower()]
        story.append(Paragraph("Detailed Security Findings List", h1_style))
        if not display_findings:
            story.append(Paragraph("No Low or higher severity findings were identified.", body_style))

    # Monospace style for HTTP payloads. Rendered as standalone story flowables (not table
    # cells) so long request/response content can SPLIT across pages — a table row cannot,
    # which previously raised a LayoutError on findings with large HTTP messages.
    code_style = ParagraphStyle(
        'CodeBlock',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=7,
        leading=9,
        textColor=dark_gray,
        backColor=light_bg,
        borderPadding=6,
        leftIndent=4,
        spaceAfter=10,
    )

    # Cap for content placed inside (non-splittable) table cells, so a single row can never
    # exceed a page height.
    def cap(text, limit=1200):
        text = text or ""
        return text[:limit] + (" ..." if len(text) > limit else "")

    for idx, finding in enumerate(display_findings, 1):
        severity = finding.get("risk", "Low")
        is_fp = finding.get("is_false_positive", False)
        
        # Header block for the finding
        if is_fp:
            sev_color = colors.HexColor("#718096")  # Neutral Slate Gray for False Positives
            header_text = f"{idx}. [FALSE POSITIVE] {esc(finding.get('alert', 'Vulnerability'))}"
        else:
            sev_color = get_severity_color(severity)
            header_text = f"{idx}. [{esc(severity).upper()}] {esc(finding.get('alert', 'Vulnerability'))}"
            
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
        affected = finding.get("affected_urls", [finding.get("url", "N/A")])
        if len(affected) > 1:
            max_pdf_urls = 15
            display_urls = affected[:max_pdf_urls]
            urls_escaped = "<br/>".join(f"• {esc(u)}" for u in display_urls)
            if len(affected) > max_pdf_urls:
                urls_escaped += f"<br/><i>... and {len(affected) - max_pdf_urls} more affected endpoints (refer to JSON report or Web Dashboard for full list)</i>"
            detail_rows.append([Paragraph("<b>Affected URLs:</b>", meta_label_style), Paragraph(urls_escaped, meta_val_style)])
        else:
            detail_rows.append([Paragraph("<b>URL:</b>", meta_label_style), Paragraph(esc(finding.get("url", "N/A")), meta_val_style)])

        if finding.get("parameter"):
            detail_rows.append([Paragraph("<b>Parameter:</b>", meta_label_style), Paragraph(esc(finding.get("parameter", "")), meta_val_style)])

        detail_rows.append([Paragraph("<b>Description:</b>", meta_label_style), Paragraph(esc(finding.get("description", "")), meta_val_style)])
        detail_rows.append([Paragraph("<b>Remediation:</b>", meta_label_style), Paragraph(esc(finding.get("solution", "")), meta_val_style)])

        # Vulnerability mappings (CVE, CWE, OWASP Top 10)
        if finding.get("cwe_full"):
            detail_rows.append([Paragraph("<b>CWE Mapping:</b>", meta_label_style), Paragraph(esc(finding.get("cwe_full")), meta_val_style)])
        if finding.get("owasp_full"):
            detail_rows.append([Paragraph("<b>OWASP Top 10:</b>", meta_label_style), Paragraph(esc(finding.get("owasp_full")), meta_val_style)])
        if finding.get("cve_full") and finding.get("cve_full") != "N/A":
            detail_rows.append([Paragraph("<b>CVE Reference:</b>", meta_label_style), Paragraph(esc(finding.get("cve_full")), meta_val_style)])

        if finding.get("evidence"):
            detail_rows.append([Paragraph("<b>Evidence:</b>", meta_label_style), Paragraph(f"<font face='Courier' size='8'>{esc(cap(finding.get('evidence', '')))}</font>", meta_val_style)])

        # AI validation sections (strictly conditional on ai_used)
        if ai_used and "ai_confidence" in finding:
            conf_color = "#38A169" if float(finding.get("ai_confidence", 0.0)) >= 0.7 else "#DD6B20"
            conf_str = f"<font color='{conf_color}'><b>{int(finding.get('ai_confidence', 0.0)*100)}%</b></font>"
            if finding.get("is_false_positive"):
                conf_str += " (AI Flagged: PROBABLE FALSE POSITIVE)"
            else:
                conf_str += " (AI Verified: TRUE POSITIVE)"
            detail_rows.append([Paragraph("<b>AI Verification:</b>", meta_label_style), Paragraph(conf_str, meta_val_style)])
            
            if finding.get("ai_reasoning"):
                detail_rows.append([Paragraph("<b>AI Validation Justification:</b>", meta_label_style), Paragraph(esc(finding.get("ai_reasoning", "")), meta_val_style)])

        if not is_executive and not finding.get("cwe_full"):
            meta_links = []
            if finding.get("cweid"):
                meta_links.append(f"CWE-{finding.get('cweid')}")
            if finding.get("wascid"):
                meta_links.append(f"WASC-{finding.get('wascid')}")
            if meta_links:
                detail_rows.append([Paragraph("<b>Reference:</b>", meta_label_style), Paragraph(", ".join(meta_links), meta_val_style)])

        # splitInRow=1 lets a single tall cell (a long Description/Remediation/AI
        # justification) break across pages. Without it, any finding whose text
        # exceeds one page height raises a reportlab LayoutError, because a table
        # row is otherwise indivisible.
        details_table = Table(detail_rows, colWidths=[100, 404], splitInRow=1)
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

        # HTTP request/response payloads (Technical report only) are rendered as standalone
        # flowables AFTER the details table so they can split across pages. Placing them in a
        # table cell (which cannot split) is what raised the LayoutError on large messages.
        http_flowables = []
        if not is_executive:
            if finding.get("request_header"):
                # Escape first so raw HTTP content is literal, then turn real newlines into
                # <br/> line breaks that reportlab understands.
                req_text = f"<b>HEADERS:</b><br/>{esc(finding.get('request_header')).replace(chr(10), '<br/>')}"
                if finding.get("request_body"):
                    req_text += f"<br/><br/><b>BODY:</b><br/>{esc(cap(finding.get('request_body'), 2000)).replace(chr(10), '<br/>')}"
                http_flowables.append(Paragraph("<b>HTTP Request:</b>", meta_label_style))
                http_flowables.append(Paragraph(req_text, code_style))

            if finding.get("response_header"):
                res_text = f"<b>HEADERS:</b><br/>{esc(finding.get('response_header')).replace(chr(10), '<br/>')}"
                if finding.get("response_body"):
                    res_body_preview = esc(cap(finding.get('response_body'), 1500)).replace(chr(10), '<br/>')
                    res_text += f"<br/><br/><b>BODY PREVIEW:</b><br/>{res_body_preview}"
                http_flowables.append(Paragraph("<b>HTTP Response:</b>", meta_label_style))
                http_flowables.append(Paragraph(res_text, code_style))

        # Glue the coloured header to the details table via keepWithNext (so the header is
        # never orphaned at a page bottom) WITHOUT forcing the whole finding onto one page —
        # the details table splits across pages on its own via splitInRow. Wrapping both in
        # KeepTogether would defeat that split and reintroduce the LayoutError on long findings.
        header_table.keepWithNext = 1
        story.append(header_table)
        story.append(details_table)
        for fl in http_flowables:
            story.append(fl)
        story.append(Spacer(1, 15))

    # Informational findings are collapsed into a single grouped summary table
    # (by alert type) rather than being rendered one-by-one.
    if info_findings:
        counts = {}
        for f in info_findings:
            name = f.get("alert") or "Uncategorized"
            counts[name] = counts.get(name, 0) + 1

        story.append(Spacer(1, 10))
        story.append(Paragraph("Informational Findings Summary", h1_style))
        story.append(Paragraph(
            f"{len(info_findings)} informational findings were identified across "
            f"{len(counts)} distinct types during passive analysis. They are grouped "
            "by type below; individual instances are available in the JSON report.",
            body_style
        ))
        story.append(Spacer(1, 10))

        info_rows = [[
            Paragraph("<b>Finding Type</b>", meta_label_style),
            Paragraph("<b>Instances</b>", meta_label_style)
        ]]
        for name, count in sorted(counts.items(), key=lambda item: item[1], reverse=True):
            info_rows.append([
                Paragraph(esc(name), body_style),
                Paragraph(str(count), body_style)
            ])

        info_table = Table(info_rows, colWidths=[420, 84], repeatRows=1)
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), light_bg),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, light_bg]),
        ]))
        story.append(info_table)

    doc.build(story, canvasmaker=NumberedCanvas)
