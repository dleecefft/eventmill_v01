#!/usr/bin/env python
"""Quick PDF report checker"""
from pypdf import PdfReader

pdf_path = r'C:\Users\mojicv\Downloads\exports_pcap_ai_analyzer_pcap_ai_analyzer_ot_triage_20260715_165745.pdf'

with open(pdf_path, 'rb') as f:
    pdf = PdfReader(f)
    print(f"\n{'='*80}")
    print(f"📄 Report: {pdf_path.split(chr(92))[-1]}")
    print(f"📊 Total Pages: {len(pdf.pages)}")
    print(f"{'='*80}\n")
    
    # Extract text from all pages
    for i in range(len(pdf.pages)):
        print(f"\n--- PAGE {i+1} of {len(pdf.pages)} ---\n")
        text = pdf.pages[i].extract_text()
        if text:
            # Show first 1000 chars per page
            print(text[:1000])
            if len(text) > 1000:
                print(f"\n... ({len(text) - 1000} more characters)")
        else:
            print("(No text extracted - may be image-based)")
    
    print(f"\n{'='*80}")
    print("✓ PDF appears valid and readable")
