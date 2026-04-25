import xml.sax.saxutils as saxutils

TABLE_W = 9360
col_widths = [2400, 2200, 3000, 1760]

BORDER = '<w:tcBorders><w:top w:val="single" w:sz="1" w:space="0" w:color="999999"/><w:left w:val="single" w:sz="1" w:space="0" w:color="999999"/><w:bottom w:val="single" w:sz="1" w:space="0" w:color="999999"/><w:right w:val="single" w:sz="1" w:space="0" w:color="999999"/></w:tcBorders>'
MARGIN = '<w:tcMar><w:top w:w="60" w:type="dxa"/><w:left w:w="100" w:type="dxa"/><w:bottom w:w="60" w:type="dxa"/><w:right w:w="100" w:type="dxa"/></w:tcMar>'
HDR_FILL = '<w:shd w:val="clear" w:color="auto" w:fill="1B2A4A"/>'
YOUR_FILL = '<w:shd w:val="clear" w:color="auto" w:fill="FFF2CC"/>'

pid = [0x16D00001]
def np():
    pid[0] += 1
    return f'{pid[0]:08X}'

def hcell(text, w):
    t = saxutils.escape(text)
    return f'<w:tc><w:tcPr><w:tcW w:w="{w}" w:type="dxa"/>{BORDER}{HDR_FILL}{MARGIN}</w:tcPr><w:p w14:paraId="{np()}" w14:textId="77777777" w:rsidR="00A108AD" w:rsidRDefault="00A108AD"><w:r><w:rPr><w:b/><w:bCs/><w:color w:val="FFFFFF"/><w:sz w:val="20"/><w:szCs w:val="20"/></w:rPr><w:t>{t}</w:t></w:r></w:p></w:tc>'

def dcell(text, w, your_val=False):
    t = saxutils.escape(str(text))
    fill = YOUR_FILL if your_val else ''
    color = '<w:color w:val="CC0000"/>' if your_val else ''
    return f'<w:tc><w:tcPr><w:tcW w:w="{w}" w:type="dxa"/>{BORDER}{fill}{MARGIN}</w:tcPr><w:p w14:paraId="{np()}" w14:textId="77777777" w:rsidR="00A108AD" w:rsidRDefault="00A108AD"><w:r><w:rPr>{color}<w:sz w:val="20"/><w:szCs w:val="20"/></w:rPr><w:t xml:space="preserve">{t}</w:t></w:r></w:p></w:tc>'

def make_table(header_labels, rows_data):
    grid = ''.join(f'<w:gridCol w:w="{w}"/>' for w in col_widths)
    lines = [f'<w:tbl><w:tblPr><w:tblW w:w="{TABLE_W}" w:type="dxa"/><w:tblBorders><w:top w:val="single" w:sz="4" w:space="0" w:color="auto"/><w:left w:val="single" w:sz="4" w:space="0" w:color="auto"/><w:bottom w:val="single" w:sz="4" w:space="0" w:color="auto"/><w:right w:val="single" w:sz="4" w:space="0" w:color="auto"/><w:insideH w:val="single" w:sz="4" w:space="0" w:color="auto"/><w:insideV w:val="single" w:sz="4" w:space="0" w:color="auto"/></w:tblBorders><w:tblCellMar><w:left w:w="10" w:type="dxa"/><w:right w:w="10" w:type="dxa"/></w:tblCellMar><w:tblLook w:val="0000" w:firstRow="0" w:lastRow="0" w:firstColumn="0" w:lastColumn="0" w:noHBand="0" w:noVBand="0"/></w:tblPr><w:tblGrid>{grid}</w:tblGrid>']
    hdr = ''.join(hcell(h, w) for h, w in zip(header_labels, col_widths))
    lines.append(f'<w:tr w:rsidR="00A108AD" w14:paraId="{np()}" w14:textId="77777777">{hdr}</w:tr>')
    for param, val, desc in rows_data:
        cells = dcell(param, col_widths[0]) + dcell(val, col_widths[1]) + dcell(desc, col_widths[2]) + dcell('', col_widths[3], your_val=True)
        lines.append(f'<w:tr w:rsidR="00A108AD" w14:paraId="{np()}" w14:textId="77777777">{cells}</w:tr>')
    lines.append('</w:tbl>')
    return '\n'.join(lines)

parts = []

parts.append(f'<w:p w14:paraId="{np()}" w14:textId="77777777" w:rsidR="00A108AD" w:rsidRDefault="00A108AD"><w:pPr><w:pStyle w:val="Heading1"/></w:pPr><w:r><w:t>13. Regulatory Exposure (C2 Jurisdiction Model)</w:t></w:r></w:p>')

parts.append(f'<w:p w14:paraId="{np()}" w14:textId="77777777" w:rsidR="00A108AD" w:rsidRDefault="00A108AD"><w:pPr><w:spacing w:after="80"/></w:pPr><w:r><w:rPr><w:sz w:val="20"/><w:szCs w:val="20"/></w:rPr><w:t xml:space="preserve">Each jurisdiction is computed independently and summed into C2. This replaces the previous multiplier approach. POPIA is always applied. GDPR and PCI are toggled via scanner UI checkboxes. Fines from different regulators genuinely stack (POPIA fines for SA data protection, PCI for card data, GDPR for EU data).</w:t></w:r></w:p>')

rows = [
    ('POPIA (always applied)', 'min(R10M, rev x 2%)', 'SA Information Regulator, Section 107. Capped at R10M statutory maximum.'),
    ('GDPR (if EU data processed)', 'rev x 4% (uncapped)', 'EU third-party liability. Not directly enforceable against SA entities without EU presence, but EU data subjects can pursue claims.'),
    ('PCI DSS (if card data)', 'R1M x (1 - adj_compliance)', 'Card scheme fines. External scanner visibility capped at 30% of PCI requirements. Fine range R700K-R1M from external assessment alone.'),
    ('PCI external visibility cap', '30%', 'Scanner covers ~10 of ~250 PCI sub-requirements. Full assessment requires internal audit to reduce fine estimate below R700K.'),
    ('Other jurisdictions', 'R2M per jurisdiction', 'Per additional regulated market where company has legal entity (UK, US states, Australia, etc.).'),
]

parts.append(make_table(['Jurisdiction', 'Calculation', 'Description', 'Your Value'], rows))

parts.append(f'<w:p w14:paraId="{np()}" w14:textId="77777777" w:rsidR="00A108AD" w:rsidRDefault="00A108AD"><w:pPr><w:spacing w:before="80" w:after="80"/></w:pPr><w:r><w:rPr><w:i/><w:iCs/><w:color w:val="666666"/><w:sz w:val="18"/><w:szCs w:val="18"/></w:rPr><w:t xml:space="preserve">Example: SA company processing EU personal data with PCI card processing. C2 = min(R10M, R200M x 2%) + R200M x 4% + R1M x 0.85 = R4M + R8M + R850K = R12.85M total regulatory exposure.</w:t></w:r></w:p>')

with open('section13_xml.txt', 'w', encoding='utf-8') as f:
    f.write('\n'.join(parts))
print(f'Generated {len(rows)} rows')
