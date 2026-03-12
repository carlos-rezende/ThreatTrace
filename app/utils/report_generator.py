"""
Gerador de relatórios em JSON e PDF
"""
import json
from io import BytesIO
from datetime import datetime

from app.schemas.threat_schema import ThreatLookupResponse


class ReportGenerator:
    """Gera relatórios de análise de threat intelligence"""
    
    @staticmethod
    def to_json(response: ThreatLookupResponse) -> str:
        """Exporta resultado em JSON"""
        data = response.model_dump()
        return json.dumps(data, indent=2, ensure_ascii=False)
    
    @staticmethod
    def to_pdf(response: ThreatLookupResponse) -> bytes:
        """Exporta resultado em PDF usando ReportLab"""
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import cm
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        except ImportError:
            raise ImportError("reportlab is required for PDF export. Install with: pip install reportlab")
        
        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=2*cm,
            leftMargin=2*cm,
            topMargin=2*cm,
            bottomMargin=2*cm,
        )
        
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(name="CustomTitle", parent=styles["Heading1"], fontSize=18, spaceAfter=12)
        heading_style = ParagraphStyle(name="CustomHeading", parent=styles["Heading2"], fontSize=14, spaceAfter=8)
        
        story = []
        story.append(Paragraph("ThreatTrace - Relatório de Threat Intelligence", title_style))
        story.append(Paragraph(f"Gerado em: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", styles["Normal"]))
        story.append(Spacer(1, 12))
        
        story.append(Paragraph(f"Consulta: {response.query} ({response.query_type})", heading_style))
        story.append(Spacer(1, 8))
        
        # URLs Maliciosas
        story.append(Paragraph("URLs Maliciosas", heading_style))
        if response.malicious_urls:
            url_data = [["URL", "Família", "Status", "First Seen"]]
            for u in response.malicious_urls[:50]:
                url_data.append([
                    u.url[:60] + "..." if len(u.url) > 60 else u.url,
                    u.malware_family or "-",
                    u.status,
                    u.first_seen or "-"
                ])
            t = Table(url_data, colWidths=[8*cm, 3*cm, 2*cm, 3*cm])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
            ]))
            story.append(t)
        else:
            story.append(Paragraph("Nenhuma URL maliciosa encontrada.", styles["Normal"]))
        story.append(Spacer(1, 12))
        
        # Campanhas
        story.append(Paragraph("Campanhas Identificadas", heading_style))
        if response.campaigns:
            camp_data = [["Família", "Domínios Relacionados", "URLs", "First/Last Seen"]]
            for c in response.campaigns:
                domains_str = ", ".join(c.related_domains[:5]) if c.related_domains else "-"
                if len(domains_str) > 40:
                    domains_str = domains_str[:40] + "..."
                dates = f"{c.first_seen or '-'} / {c.last_seen or '-'}"
                camp_data.append([c.family, domains_str, str(c.url_count), dates])
            t = Table(camp_data, colWidths=[3*cm, 6*cm, 2*cm, 5*cm])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                ("BACKGROUND", (0, 1), (-1, -1), colors.lightblue),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
            ]))
            story.append(t)
        else:
            story.append(Paragraph("Nenhuma campanha identificada.", styles["Normal"]))
        story.append(Spacer(1, 12))
        
        # Infraestrutura
        if response.infrastructure:
            story.append(Paragraph("Infraestrutura Descoberta", heading_style))
            infra = response.infrastructure
            lines = []
            if infra.domains:
                lines.append(f"Domínios: {', '.join(infra.domains[:20])}")
            if infra.ips:
                lines.append(f"IPs: {', '.join(infra.ips[:20])}")
            if infra.shared_hosts:
                lines.append(f"Hosts compartilhados: {', '.join(infra.shared_hosts[:10])}")
            for line in lines:
                story.append(Paragraph(line, styles["Normal"]))
            story.append(Spacer(1, 12))
        
        # Timeline
        if response.timeline:
            story.append(Paragraph("Linha do Tempo", heading_style))
            timeline_data = [["Data", "Tipo", "Descrição", "URLs"]]
            for ev in response.timeline[:20]:
                timeline_data.append([ev.date, ev.event_type, ev.description[:40], str(ev.url_count)])
            t = Table(timeline_data, colWidths=[3*cm, 3*cm, 6*cm, 2*cm])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
            ]))
            story.append(t)
        
        doc.build(story)
        return buffer.getvalue()
