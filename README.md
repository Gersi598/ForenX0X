# ForenX0X
# ForenX0X - CTF Forensics Automation Toolkit

### Created by Gersi Hajrullahi

---

## About

**ForenX0X** is an advanced forensic automation tool tailored for **Capture The Flag (CTF)** challenges.  
It automatically analyzes files for hidden flags using steganography, document analysis, network forensics, and more.

ForenX0X supports both **CLI** and **GUI** modes, providing modular plugin-based analysis.

---

## Techniques and Features

### 🔍 Steganography
- LSB steganography (stepic, stegolsb, zsteg)
- Hidden data in PNG chunks, JPEG quantization, alpha channels
- Detection of appended data beyond file end
- Audio/video steganography analysis (ffmpeg extracted)
- OCR on images, enhanced OCR (contrast/sharpness)
- QR code extraction

### 📑 Metadata and File Analysis
- exiftool metadata extraction
- File magic signature mismatch detection
- HTML JavaScript obfuscation analysis

### 📄 Document Analysis
- Detection of embedded Office macros (olevba)
- Hidden formulas and alt-text in Office files
- Analysis of embedded files in Office and PDF documents

### 📂 Archive & Bomb Detection
- Extraction and analysis of nested archives
- Entropy analysis to detect compression/encryption bombs

### 🌐 Network Forensics
- HTTP/DNS/SMTP/FTP sessions from PCAP files (tshark)
- HTTP object carving
- TCP stream reconstruction

### 🧠 Memory Forensics
- Volatility3 basic memory dump analysis

### 🤖 Machine Learning
- Artifact prioritization (files scored based on entropy, size, etc.)

### 🎨 GUI (Tkinter)
- Plugin-based selection
- Live progress and log window
- Dark/Light themes
- Auto-open PDF report
- Visual spinner

---

## Installation

Clone the repository and install Python requirements:

```bash
pip install -r requirements.txt

