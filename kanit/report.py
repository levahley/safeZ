"""Portable PDF report; only persisted, masked evidence is printed."""
import html
import io
from datetime import datetime, timezone, timedelta
from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether

SEVERITY = {'critical': 'Kritik', 'high': 'Yüksek', 'medium': 'Orta', 'low': 'Düşük', 'info': 'Bilgi'}
STATE = {'tested': 'Test edildi', 'skipped': 'Atlandı', 'inconclusive': 'Sonuçsuz', 'not_implemented': 'Uygulanmadı'}


def make_pdf(job):
    font_dir = Path(__file__).parent.parent / 'assets'
    for name, filename in [('SafeZ', 'NotoSans-Regular.ttf'), ('SafeZBold', 'NotoSans-Bold.ttf')]:
        if name not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont(name, str(font_dir / filename)))
    pdfmetrics.registerFontFamily('SafeZ', normal='SafeZ', bold='SafeZBold', italic='SafeZ', boldItalic='SafeZBold')
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='BodyTR', fontName='SafeZ', fontSize=9, leading=14, textColor=colors.HexColor('#23334d'), spaceAfter=7))
    styles.add(ParagraphStyle(name='TitleTR', fontName='SafeZBold', fontSize=24, leading=29, textColor=colors.HexColor('#142746'), spaceAfter=12))
    styles.add(ParagraphStyle(name='HeadTR', fontName='SafeZBold', fontSize=14, leading=19, spaceBefore=14, spaceAfter=8, textColor=colors.HexColor('#142746')))
    styles.add(ParagraphStyle(name='SmallTR', fontName='SafeZ', fontSize=7.5, leading=11, spaceAfter=4))
    def p(text, style='BodyTR'):
        return Paragraph(html.escape(str(text)).replace('\n', '<br/>'), styles[style])
    report = job.get('report') or {}
    findings = report.get('findings', [])
    verified_high = sum(f['status'] == 'confirmed' and f['severity'] in ('critical', 'high') for f in findings)
    date = datetime.fromtimestamp(job.get('created_at', 0), timezone(timedelta(hours=3))).strftime('%d.%m.%Y %H:%M')
    stream = io.BytesIO()
    doc = SimpleDocTemplate(stream, pagesize=A4, rightMargin=43, leftMargin=43, topMargin=49, bottomMargin=43, title='safeZ - güvenlik inceleme raporu', author='safeZ')
    story = [p('safeZ', 'TitleTR'), p('Güvenlik inceleme raporu', 'HeadTR'), p(report.get('origin', job.get('origin', ''))), p(date + ' (Türkiye saati) | Tarama: ' + job.get('status', '') + ' | İstek: ' + str(report.get('requests', 0))), p(str(verified_high) + ' doğrulanmış yüksek/kritik risk', 'HeadTR'), p('Bulgu sayıları yalnızca tekrarlanabilir kontrollü karşılaştırmaları kapsar. Pasif motor uyarıları bu toplama katılmaz.'), p(report.get('conclusion', 'Bu inceleme sitenin tamamen güvenli olduğunu göstermez.'))]
    if job.get('status') != 'complete':
        story.append(p('Tarama tamamlanmadı. Aşağıdaki sonuçlar kısmi incelemeye aittir.'))
    for warning in report.get('warnings', []):
        story.append(p('Sınır / uyarı: ' + warning))
    if not findings:
        story.append(p('Kontrollü testlerde doğrulanmış açık bulunmadı. Yapılamayan ve kapsam dışı testleri aşağıda inceleyin.'))
    for index, f in enumerate(findings, 1):
        status_label = 'Doğrulanmış' if f['status'] == 'confirmed' else 'Şüpheli'
        story.extend([p(str(index) + '. ' + f['title'], 'HeadTR'), p(SEVERITY.get(f['severity'], f['severity']) + ' | ' + status_label + ' | ' + str(f['repeats']) + ' karşılaştırma turu'), p('Etkilenen adres: ' + f['url']), p('Parametre: ' + (f.get('parameter') or 'Yok')), p('Konum: GET ' + f.get('location', {}).get('endpoint', f['url']) + (' | Yanıt satırı: ' + str(f['location']['response_line']) if f.get('location', {}).get('response_line') else '')), p('Sorun nedir? ' + f['condition']), p('Ne olabilir? ' + f['impact']), p('Nasıl düzeltilir? ' + f['fix']), p('Güvenli tekrar üretme', 'HeadTR')])
        for step_index, step in enumerate(f['steps'], 1):
            story.append(p(str(step_index) + ') ' + step))
        if f.get('english'):
            english = f['english']
            story.extend([p('English: ' + english['title'], 'HeadTR'), p('Observed behavior: ' + english['condition']), p('Impact: ' + english['impact']), p('Remediation: ' + english['fix'])])
            story.extend(p(str(i) + ') ' + step) for i, step in enumerate(english['steps'], 1))
        story.append(p('Maskelenmiş teknik kanıt', 'HeadTR'))
        table_rows = [[p('Kontrol', 'SmallTR'), p('HTTP', 'SmallTR'), p('İşaretleyici', 'SmallTR'), p('Yanıt SHA-256 (ilk 16)', 'SmallTR')]]
        for e in f['evidence']:
            present = ('Var' if e['marker_present'] else 'Yok') if 'marker_present' in e else '-'
            table_rows.append([p(e['test'] + ('\nGET ' + e['request'] if e.get('request') else ''), 'SmallTR'), p(e['http_status'], 'SmallTR'), p(present, 'SmallTR'), p(e['sha256'][:16], 'SmallTR')])
        table = Table(table_rows, colWidths=[211, 38, 62, 198], repeatRows=1, hAlign='LEFT')
        table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#eaf0fa')), ('VALIGN', (0, 0), (-1, -1), 'TOP'), ('BOTTOMPADDING', (0, 0), (-1, -1), 7), ('TOPPADDING', (0, 0), (-1, -1), 7), ('LINEBELOW', (0, 0), (-1, -1), .4, colors.HexColor('#d5deeb'))]))
        story.extend([table, Spacer(1, 10), p('Yanıt gövdeleri, oturum çerezleri ve işaretleyici değerleri saklanmaz. SHA-256 bütünlük özeti kanıtı bağlar; özgün içerik yerine geçmez.', 'SmallTR')])
    if report.get('relationships'):
        story.append(p('Bulgular arası ilişki', 'HeadTR'))
        story.extend(p(x) for x in report['relationships'])
    story.append(p('Test kapsamı ve sınırlar', 'HeadTR'))
    for c in report.get('coverage', []):
        story.extend([p(c['name'] + ' - ' + STATE.get(c['state'], c['state'])), p(c['detail'], 'SmallTR'), p(str(c.get('requests', 0)) + ' GET isteği', 'SmallTR')])
        if c.get('detail_en'):
            story.append(p(c.get('name_en', c['kind']) + ': ' + c['detail_en'], 'SmallTR'))
    engine = report.get('engine', {})
    story.extend([p('Pasif motor', 'HeadTR'), p(engine.get('name', 'OWASP ZAP') + ': ' + engine.get('detail', 'Çalışmadı.'))])
    for a in report.get('passive_alerts', []):
        story.extend([p(a['title'] + ' - Şüpheli (' + SEVERITY.get(a['severity'], a['severity']) + ')'), p(a['url'], 'SmallTR'), p(a['note'], 'SmallTR'), p('Çözüm: ' + a['fix'], 'SmallTR')])
        if a.get('english'):
            story.extend([p('English: ' + a['english']['title'], 'SmallTR'), p(a['english']['impact'], 'SmallTR'), p('Remediation: ' + a['english']['fix'], 'SmallTR')])
    story.append(p('Keşif: ' + str(len(report.get('discovery', {}).get('pages', []))) + ' yanıt, ' + str(len(report.get('discovery', {}).get('forms', []))) + ' form. Formlar keşfedildi; POST/yazma işlemleri gönderilmedi.'))
    def footer(canvas, document):
        canvas.setFont('SafeZ', 8)
        canvas.setFillColor(colors.HexColor('#61718a'))
        canvas.drawString(43, 24, 'safeZ | Maskelenmiş test kanıtları')
        canvas.drawRightString(A4[0] - 43, 24, str(document.page))
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return stream.getvalue()
