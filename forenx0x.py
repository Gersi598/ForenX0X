import os
import sys
import base64
import datetime
import subprocess
import re
from PIL import Image
from stepic import decode as stepic_decode_internal
from fpdf import FPDF


YELLOW = "\033[93m"
RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"

def info(msg): print(f"{YELLOW}[+] {msg}{RESET}")
def warn(msg): print(f"{RED}[!] {msg}{RESET}")
def success(msg): print(f"{GREEN}[✓] {msg}{RESET}")

def run_cmd(cmd, cwd=None):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=cwd)
        return result.stdout
    except Exception as e:
        return str(e)


PLUGINS = []
REPORT_LINES = []


def register_plugin(func):
    PLUGINS.append(func)
    return func

def print_banner():
    line = "*" * 91
    text = "This script was created by Gersi Hajrullahi as part of CTF challenge automation."
    print(f"\n{YELLOW}{line}{RESET}")
    print(f"{YELLOW}{text.center(len(line))}{RESET}")
    print(f"{YELLOW}{line}{RESET}\n")

def analyze_output_for_flags(label, output, variants):
    if not output.strip():
        warn(f"No output from {label}.")
        return

    matches_found = False

    
    for variant in variants:
        if variant in output:
            success(f"Match found in {label} [format: direct string]")
            for line in output.splitlines():
                if variant in line:
                    match_line = f"{variant} ← found in: {line.strip()}"
                    print(GREEN + "    " + match_line + RESET)
                    REPORT_LINES.append((label, variant, "string", line.strip()))
            matches_found = True

    
    b64_strings = re.findall(r'[A-Za-z0-9+/=]{8,}', output)
    for b64 in b64_strings:
        try:
            decoded = base64.b64decode(b64).decode("utf-8", errors="ignore")
            for variant in variants:
                if variant in decoded:
                    success(f"Base64-decoded match in {label}")
                    REPORT_LINES.append((label, variant, "base64", decoded.strip()))
                    print(GREEN + f"    {variant} ← decoded from base64: {b64}" + RESET)
                    print(GREEN + f"       Decoded content: {decoded.strip()}" + RESET)
                    matches_found = True
        except Exception:
            continue

    
    hex_strings = re.findall(r'(?:[0-9a-fA-F]{2}){4,}', output)
    for hexstr in hex_strings:
        try:
            decoded = bytes.fromhex(hexstr).decode("utf-8", errors="ignore")
            for variant in variants:
                if variant in decoded:
                    success(f"Hex-decoded match in {label}")
                    REPORT_LINES.append((label, variant, "hex", decoded.strip()))
                    print(GREEN + f"    {variant} ← decoded from hex: {hexstr}" + RESET)
                    print(GREEN + f"       Decoded content: {decoded.strip()}" + RESET)
                    matches_found = True
        except Exception:
            continue

    if not matches_found:
        warn(f"No flag-like matches found in {label}.")



@register_plugin
def detect_appended_data(file, variants):
    info("Detecting and printing appended data after EOF...")
    try:
        with open(file, "rb") as f:
            data = f.read()
        eof_offset = data.find(b'\x00\x00\x00\x00')
        if eof_offset != -1:
            extra_data = data[eof_offset+4:]
            output = extra_data.decode("utf-8", errors="ignore")
            analyze_output_for_flags("Appended Data", output, variants)
        else:
            warn("No clear EOF marker found.")
    except Exception as e:
        warn(f"Appended data check failed: {e}")

@register_plugin
def analyze_png_chunks(file, variants):
    info("Analyzing PNG chunks for hidden data...")
    result = run_cmd(f"pngcheck -v {file}")
    analyze_output_for_flags("PNG chunk analysis", result, variants)

@register_plugin
def analyze_jpeg_quantization(file, variants):
    info("Checking JPEG quantization tables for anomalies...")
    result = run_cmd(f"exiftool -JPEGQTable {file}")
    analyze_output_for_flags("JPEG quantization", result, variants)

@register_plugin
def stegseek_crack(file, wordlist="rockyou.txt", variants=[]):
    info("Running stegseek for steghide-cracked images...")
    output_dir = "stegseek_output"
    os.makedirs(output_dir, exist_ok=True)
    result = run_cmd(f"stegseek --quiet --crack {file} {wordlist} -xf {output_dir}/found.txt")
    if os.path.exists(f"{output_dir}/found.txt"):
        with open(f"{output_dir}/found.txt", "r") as f:
            content = f.read()
        analyze_output_for_flags("stegseek cracked content", content, variants)
    else:
        warn("No output from stegseek or file not cracked.")

@register_plugin
def extract_alpha_or_icc(file, variants):
    info("Extracting alpha channel or ICC profile data...")
    result = run_cmd(f"identify -verbose {file}")
    analyze_output_for_flags("Alpha/ICC metadata", result, variants)

@register_plugin
def analyze_magic_mismatch(file, variants):
    info("Checking file signature vs extension...")
    output = run_cmd(f"binwalk -B {file}")
    analyze_output_for_flags("Magic mismatch analysis", output, variants)

@register_plugin
def scan_html_for_obfuscated_js(file, variants):
    info("Looking for obfuscated JavaScript in HTML...")
    content = run_cmd(f"cat {file}")
    js_blocks = re.findall(r'<script.*?>.*?</script>', content, re.DOTALL | re.IGNORECASE)
    for block in js_blocks:
        analyze_output_for_flags("HTML JavaScript block", block, variants)

def generate_flag_variants(flag_prefix):
    variants = set()
    variants.add(flag_prefix)
    variants.add(flag_prefix[::-1])  # reversed
    variants.add(base64.b64encode(flag_prefix.encode()).decode())
    variants.add(flag_prefix.encode().hex())

    
    unicode_variant = ''.join('\\u{:04x}'.format(ord(c)) for c in flag_prefix)
    hex_variant = ''.join('\\x{:02x}'.format(ord(c)) for c in flag_prefix)

    variants.add(unicode_variant)
    variants.add(hex_variant)

    return variants

@register_plugin
def binwalk_analysis(filename, variants):
    info("Running binwalk...")
    run_cmd(f"binwalk -e {filename}")
    extracted_dir = f"_{filename}.extracted"

    if os.path.isdir(extracted_dir):
        for root, _, files in os.walk(extracted_dir):
            for file in files:
                path = os.path.join(root, file)
                info(f"Analyzing extracted file: {path}")
                strings_output = run_cmd(f"strings '{path}'")
                analyze_output_for_flags(f"strings on {file}", strings_output, variants)

                xxd_output = run_cmd(f"xxd '{path}'")
                analyze_output_for_flags(f"xxd on {file}", xxd_output, variants)
    else:
        warn("No binwalk-extracted directory found.")

@register_plugin
def zsteg_analysis(filename, variants):
    info("Running zsteg...")
    result = run_cmd(f"zsteg -a {filename}")
    analyze_output_for_flags("zsteg", result, variants)

@register_plugin
def stegolsb_analysis(filename, variants):
    info("Running stegolsb bit plane analysis...")
    for method in ['lsb', 'lsb-set', 'lsb-r', 'lsb-r-set']:
        info(f"Method: {method}")
        result = run_cmd(f"stegolsb extract -i {filename} -m {method} -n 1")
        analyze_output_for_flags(f"stegolsb {method}", result, variants)

@register_plugin
def stepic_decode(filename, variants):
    info("Attempting LSB decode using stepic and PIL...")
    try:
        Image.MAX_IMAGE_PIXELS = None
        img = Image.open(filename)
        hidden = stepic_decode_internal(img)
        analyze_output_for_flags("stepic", hidden, variants)
    except Exception as e:
        warn(f"Stepic decoding error: {e}")

@register_plugin
def metadata_analysis(filename, variants):
    info("Running exiftool...")
    result = run_cmd(f"exiftool '{filename}'")
    analyze_output_for_flags("exiftool", result, variants)

@register_plugin
def xxd_analysis(filename, variants):
    detect_appended_data(filename, variants)
    analyze_png_chunks(filename, variants)
    analyze_jpeg_quantization(filename, variants)
    stegseek_crack(filename, "rockyou.txt", variants)
    extract_alpha_or_icc(filename, variants)
    analyze_magic_mismatch(filename, variants)
    scan_html_for_obfuscated_js(filename, variants)
    info("Running xxd hex dump...")
    result = run_cmd(f"xxd '{filename}'")
    analyze_output_for_flags("xxd", result, variants)

@register_plugin
def document_analysis(file, variants):
    info("Running oletools on document...")
    output = run_cmd(f"oleid '{file}'") + run_cmd(f"olemeta '{file}'")
    analyze_output_for_flags("oletools", output, variants)

@register_plugin
def run_volatility(memory_file, variants):
    info("Running volatility3 on memory dump...")
    result = run_cmd(f"volatility3 -f '{memory_file}' windows.info")
    analyze_output_for_flags("volatility3", result, variants)

@register_plugin
def analyze_pcap(pcap_file, variants):
    info("Analyzing PCAP file with tshark...")
    result = run_cmd(f"tshark -r '{pcap_file}' -Y 'http.request || dns || ftp || smtp'")
    analyze_output_for_flags("tshark (protocols)", result, variants)

@register_plugin
def extract_pcap_files_with_networkminer(pcap_file):
    info("[INFO] Suggest using NetworkMiner for GUI extraction from PCAP:")
    print(" -> Run: mono NetworkMiner.exe -r " + pcap_file)

@register_plugin
def extract_http_files(pcap_file, variants):
    info("Extracting HTTP files with tshark...")
    result = run_cmd(f"tshark -r '{pcap_file}' --export-objects http,http_export")
    analyze_output_for_flags("HTTP object export", result, variants)

@register_plugin
def reassemble_tcp_streams(pcap_file, variants):
    info("Reassembling TCP streams with tshark...")
    result = run_cmd(f"tshark -r '{pcap_file}' -qz follow,tcp,raw")
    analyze_output_for_flags("TCP reassembly", result, variants)

@register_plugin
def extract_with_foremost(file, variants):
    info("Carving with foremost...")
    os.makedirs("foremost_output", exist_ok=True)
    run_cmd(f"foremost -i '{file}' -o foremost_output")
    for root, _, files in os.walk("foremost_output"):
        for name in files:
            path = os.path.join(root, name)
            strings_output = run_cmd(f"strings '{path}'")
            analyze_output_for_flags(f"foremost strings {name}", strings_output, variants)

@register_plugin
def detect_polyglot_file(file, variants):
    info("Checking for known polyglot signatures (ZIP + other formats)...")
    try:
        with open(file, 'rb') as f:
            data = f.read(4096)
        if b'PK' in data and b'%PDF' in data:
            success("Polyglot detected: ZIP and PDF signatures found")
            REPORT_LINES.append(("polyglot detection", "PK+%PDF", "binary signature", "ZIP and PDF overlap"))
        elif b'PK' in data and b'7z' in data:
            success("Polyglot detected: ZIP and 7z signatures found")
            REPORT_LINES.append(("polyglot detection", "PK+7z", "binary signature", "ZIP and 7z overlap"))
        else:
            warn("No common polyglot signatures found")
    except Exception as e:
        warn(f"Polyglot detection failed: {e}")

@register_plugin
def scan_nested_archives(file, variants):
    info("Scanning for nested archives using 7z list depth...")
    try:
        result = run_cmd(f"7z l -slt '{file}'")
        analyze_output_for_flags("7z nested archive listing", result, variants)
        if result.count("Path =") > 10:
            success("Potential archive bomb: many nested files detected")
            REPORT_LINES.append(("archive depth", ">10 entries", "7z list", result[:500]))
    except Exception as e:
        warn(f"Nested archive scan failed: {e}")

@register_plugin
def entropy_analysis(file, variants):
    info("Running entropy analysis with binwalk...")
    try:
        result = run_cmd(f"binwalk --entropy '{file}'")
        analyze_output_for_flags("entropy scan", result, variants)
        if 'Entropy' in result and 'Mean' in result:
            matches = re.findall(r'Mean: ([0-9.]+)', result)
            if any(float(m) > 7.5 for m in matches):
                success("High entropy segment detected — possible encryption/compression")
                REPORT_LINES.append(("entropy alert", "mean > 7.5", "binwalk entropy", result))
    except Exception as e:
        warn(f"Entropy analysis failed: {e}")
    result = run_cmd(f"binwalk --entropy '{file}'")
    analyze_output_for_flags("entropy scan", result, variants)

@register_plugin
def unzip_recursive(file, variants):
    info("Unzipping recursively if needed...")
    run_cmd(f"7z x '{file}' -oextract_here -aoa")
    for root, _, files in os.walk("extract_here"):
        for name in files:
            path = os.path.join(root, name)
            strings_output = run_cmd(f"strings '{path}'")
            analyze_output_for_flags(f"unzipped strings {name}", strings_output, variants)

def detect_appended_data(file, variants):
    info("Detecting and printing appended data after EOF...")
    try:
        with open(file, "rb") as f:
            data = f.read()
        eof_offset = data.find(b'####')
        if eof_offset != -1:
            extra_data = data[eof_offset+4:]
            output = extra_data.decode("utf-8", errors="ignore")
            analyze_output_for_flags("Appended Data", output, variants)
        else:
            warn("No clear EOF marker found.")
    except Exception as e:
        warn(f"Appended data check failed: {e}")

def analyze_png_chunks(file, variants):
    info("Analyzing PNG chunks for hidden data...")
    result = run_cmd(f"pngcheck -v {file}")
    analyze_output_for_flags("PNG chunk analysis", result, variants)

def analyze_jpeg_quantization(file, variants):
    info("Checking JPEG quantization tables for anomalies...")
    result = run_cmd(f"exiftool -JPEGQTable {file}")
    analyze_output_for_flags("JPEG quantization", result, variants)

def stegseek_crack(file, wordlist="rockyou.txt", variants=[]):
    info("Running stegseek for steghide-cracked images...")
    output_dir = "stegseek_output"
    os.makedirs(output_dir, exist_ok=True)
    result = run_cmd(f"stegseek --quiet --crack {file} {wordlist} -xf {output_dir}/found.txt")
    if os.path.exists(f"{output_dir}/found.txt"):
        with open(f"{output_dir}/found.txt", "r") as f:
            content = f.read()
        analyze_output_for_flags("stegseek cracked content", content, variants)
    else:
        warn("No output from stegseek or file not cracked.")

def extract_alpha_or_icc(file, variants):
    info("Extracting alpha channel or ICC profile data...")
    result = run_cmd(f"identify -verbose {file}")
    analyze_output_for_flags("Alpha/ICC metadata", result, variants)

def analyze_magic_mismatch(file, variants):
    info("Checking file signature vs extension...")
    output = run_cmd(f"binwalk -B {file}")
    analyze_output_for_flags("Magic mismatch analysis", output, variants)

def scan_html_for_obfuscated_js(file, variants):
    info("Looking for obfuscated JavaScript in HTML...")
    content = run_cmd(f"cat {file}")
    js_blocks = re.findall(r'<script.*?>.*?</script>', content, re.DOTALL | re.IGNORECASE)
    for block in js_blocks:
        analyze_output_for_flags("HTML JavaScript block", block, variants)

@register_plugin
def analyze_audio_video_stego(file, variants):
    info("Analyzing for audio/video steganography...")

    # Check file type
    mime = run_cmd(f"file --mime-type -b '{file}'").strip()

    if 'audio' in mime:
        info("File is audio. Extracting raw data with ffmpeg...")
        os.makedirs("audio_extract", exist_ok=True)
        run_cmd(f"ffmpeg -i '{file}' -f wav audio_extract/out.wav -y")
        strings_output = run_cmd("strings audio_extract/out.wav")
        analyze_output_for_flags("audio strings (wav)", strings_output, variants)

    elif 'video' in mime:
        info("File is video. Extracting frames...")
        os.makedirs("video_frames", exist_ok=True)
        run_cmd(f"ffmpeg -i '{file}' video_frames/frame_%04d.png -hide_banner -loglevel error")

        frame_files = sorted(os.listdir("video_frames"))
        if not frame_files:
            warn("No frames extracted from video.")
        for frame in frame_files:
            frame_path = os.path.join("video_frames", frame)
            strings_output = run_cmd(f"strings '{frame_path}'")
            analyze_output_for_flags(f"video frame {frame}", strings_output, variants)
    else:
        warn("File is not audio or video.")
        
@register_plugin
def ocr_image_analysis(file, variants):
    info("Running OCR to extract hidden text from images...")

    try:
        from pytesseract import image_to_string, Output
        import cv2
        import numpy as np

        
        img = cv2.imread(file)
        if img is None:
            warn("Not an image file, or cannot open for OCR.")
            return

        
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

        
        _, thresh = cv2.threshold(gray, 150, 255, cv2.THRESH_BINARY)

        
        ocr_outputs = []

        text_normal = image_to_string(Image.fromarray(gray))
        if text_normal.strip():
            ocr_outputs.append(("OCR on Grayscale", text_normal))

        text_thresh = image_to_string(Image.fromarray(thresh))
        if text_thresh.strip():
            ocr_outputs.append(("OCR on Thresholded", text_thresh))

        
        for label, extracted_text in ocr_outputs:
            analyze_output_for_flags(label, extracted_text, variants)

    except ImportError:
        warn("pytesseract or OpenCV not installed. Skipping OCR analysis.")
    except Exception as e:
        warn(f"OCR analysis failed: {e}")
        

@register_plugin
def detect_qr_codes(file, variants):
    info("Scanning image for QR codes...")

    try:
        import cv2
        detector = cv2.QRCodeDetector()

        img = cv2.imread(file)
        if img is None:
            warn("Not an image file, or cannot open for QR scanning.")
            return

        data, points, _ = detector.detectAndDecode(img)
        if data:
            success("QR code detected!")
            analyze_output_for_flags("QR Code Content", data, variants)
        else:
            warn("No QR code found in the image.")

    except ImportError:
        warn("opencv-python not installed. Skipping QR detection.")
    except Exception as e:
        warn(f"QR code scan failed: {e}")


@register_plugin
def enhance_contrast_sharpness(file, variants):
    info("Enhancing image contrast and sharpness for better OCR...")

    try:
        from PIL import ImageEnhance

        img = Image.open(file)
        if img.mode != 'RGB':
            img = img.convert('RGB')

        # Apply contrast enhancement
        enhancer_contrast = ImageEnhance.Contrast(img)
        img_contrast = enhancer_contrast.enhance(2.0)

        # Apply sharpness enhancement
        enhancer_sharpness = ImageEnhance.Sharpness(img_contrast)
        img_sharp = enhancer_sharpness.enhance(2.0)

        # OCR the enhanced image
        from pytesseract import image_to_string
        text = image_to_string(img_sharp)

        if text.strip():
            analyze_output_for_flags("Enhanced OCR Text", text, variants)
        else:
            warn("No text found after enhancing contrast and sharpness.")

    except ImportError:
        warn("Pillow or pytesseract not installed. Skipping enhancement OCR.")
    except Exception as e:
        warn(f"Enhanced OCR failed: {e}")


@register_plugin
def pdf_stego_detection(file, variants):
    info("Analyzing PDF for hidden data and steganography...")
    if not file.lower().endswith(".pdf"):
        warn("Not a PDF file, skipping PDF stego analysis.")
        return

    
    result_meta = run_cmd(f"exiftool '{file}'")
    analyze_output_for_flags("PDF Metadata (exiftool)", result_meta, variants)

    
    result_info = run_cmd(f"pdfinfo '{file}'")
    analyze_output_for_flags("PDF Info (pdfinfo)", result_info, variants)

    
    os.makedirs("pdf_embedded", exist_ok=True)
    result_qpdf = run_cmd(f"qpdf --show-object=all '{file}'")
    analyze_output_for_flags("PDF Embedded Object Dump", result_qpdf, variants)

    result_pdfdetach = run_cmd(f"pdfdetach -saveall -o pdf_embedded '{file}'")
    for root, _, files in os.walk("pdf_embedded"):
        for name in files:
            path = os.path.join(root, name)
            strings_output = run_cmd(f"strings '{path}'")
            analyze_output_for_flags(f"Embedded PDF File: {name}", strings_output, variants)


@register_plugin
def office_document_stego(file, variants):
    info("Analyzing Office document for hidden content...")
    if not file.lower().endswith((".docx", ".pptx", ".xlsx")):
        warn("Not an Office document (docx/pptx/xlsx), skipping.")
        return

    os.makedirs("office_extract", exist_ok=True)
    run_cmd(f"7z x '{file}' -ooffice_extract -aoa")

    for root, _, files in os.walk("office_extract"):
        for name in files:
            path = os.path.join(root, name)
            if any(part in path for part in ["word", "ppt", "xl"]):
                strings_output = run_cmd(f"strings '{path}'")
                analyze_output_for_flags(f"Office inner file: {name}", strings_output, variants)

    
    result_vba = run_cmd(f"olevba '{file}'")
    analyze_output_for_flags("OLE VBA Macro Scan", result_vba, variants)


@register_plugin
def detect_white_text_in_pdf(file, variants):
    info("Scanning PDF for white text steganography...")
    if not file.lower().endswith(".pdf"):
        warn("Not a PDF file, skipping white text analysis.")
        return

    try:
        content = run_cmd(f"pdftotext '{file}' -")
        if not content.strip():
            warn("No visible text extracted, possible full stego.")
            return
        analyze_output_for_flags("PDF extracted visible text", content, variants)
    except Exception as e:
        warn(f"White text detection failed: {e}")


@register_plugin
def detect_hidden_formulas_in_office(file, variants):
    info("Analyzing Office document for hidden spreadsheet formulas...")
    if not file.lower().endswith(".xlsx"):
        warn("Not an Excel (.xlsx) file, skipping formula analysis.")
        return

    os.makedirs("office_formulas", exist_ok=True)
    run_cmd(f"7z x '{file}' -ooffice_formulas -aoa")

    for root, _, files in os.walk("office_formulas"):
        for name in files:
            if name.endswith(".xml") and "sheet" in name.lower():
                path = os.path.join(root, name)
                content = run_cmd(f"cat '{path}'")
                analyze_output_for_flags(f"Excel Formulas {name}", content, variants)


@register_plugin
def detect_hidden_chart_alt_text(file, variants):
    info("Searching Office charts and alt-text for hidden messages...")
    if not file.lower().endswith((".docx", ".pptx", ".xlsx")):
        warn("Not an Office document, skipping chart/alt-text analysis.")
        return

    os.makedirs("office_alttext", exist_ok=True)
    run_cmd(f"7z x '{file}' -ooffice_alttext -aoa")

    for root, _, files in os.walk("office_alttext"):
        for name in files:
            if name.endswith(".xml") and ("chart" in name.lower() or "docprops" in root):
                path = os.path.join(root, name)
                content = run_cmd(f"cat '{path}'")
                analyze_output_for_flags(f"Office Chart/Alt-Text {name}", content, variants)




def generate_pdf_report(flag_prefix):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="CTF Forensics Report", ln=True, align='C')
    pdf.cell(200, 10, txt=f"Flag format: {flag_prefix}", ln=True, align='L')
    pdf.cell(200, 10, txt=f"Generated: {datetime.datetime.now()}", ln=True, align='L')
    pdf.ln(10)

    for label, variant, ftype, content in REPORT_LINES:
        pdf.multi_cell(0, 10, f"[{label}] - Type: {ftype} - Variant: {variant} - Content: {content}")

    os.makedirs("reports", exist_ok=True)
    path = f"reports/ctf_report_{flag_prefix}.pdf"
    pdf.output(path)
    success(f"PDF report saved to {path}")


def launch_gui():
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, scrolledtext
        from PIL import Image, ImageTk
        import webbrowser, threading
        import time

        root = tk.Tk()
        root.title("CTF Forensics Toolkit by Gersi Hajrullahi")
        root.geometry("900x600")
        root.configure(bg="white")

        plugin_vars = {}

        
        def toggle_theme():
            theme = theme_var.get()
            bg = "#1e1e1e" if theme == "dark" else "white"
            fg = "white" if theme == "dark" else "black"
            log_bg = "#2e2e2e" if theme == "dark" else "white"

            root.configure(bg=bg)
            for widget in root.winfo_children():
                if isinstance(widget, (tk.Label, tk.Button, tk.Checkbutton, tk.Frame)):
                    widget.configure(bg=bg, fg=fg)
            text_log.configure(bg=log_bg, fg=fg)

        def toggle_all_plugins():
            state = select_all_var.get()
            for var in plugin_vars.values():
                var.set(state)

        def browse_file():
            file_selected = filedialog.askopenfilename()
            if file_selected:
                entry_file.delete(0, tk.END)
                entry_file.insert(0, file_selected)

        def run_analysis():
            flag_prefix = entry_flag.get()
            file_path = entry_file.get()
            auto_open = open_pdf_var.get()

            if not flag_prefix or not file_path:
                messagebox.showerror("Error", "Both fields are required!")
                return

            selected = [name for name, var in plugin_vars.items() if var.get()]
            PLUGINS[:] = [f for f in globals().values() if callable(f) and hasattr(f, "_plugin_name") and f._plugin_name in selected]

            sys.argv = [sys.argv[0], flag_prefix, file_path]
            try:
                loading_label.config(text="Analyzing...", fg="blue")
                main()
                loading_label.config(text="Analysis complete", fg="green")
                if auto_open:
                    report_path = f"reports/ctf_report_{flag_prefix}.pdf"
                    if os.path.exists(report_path):
                        webbrowser.open(report_path)
            except Exception as e:
                messagebox.showerror("Error", str(e))
                loading_label.config(text="Error occurred", fg="red")

        def start_analysis():
            threading.Thread(target=run_analysis).start()

        
        tk.Label(root, text="ForenX0X", font=("Arial", 16, "bold"), fg="#004080", bg="white").place(x=370, y=10)
        tk.Label(root, text="by Gersi Hajrullahi", font=("Arial", 10), bg="white").place(x=380, y=40)

        alb_img = Image.open("./albania.png").resize((100, 100))
        alb_img_tk = ImageTk.PhotoImage(alb_img)
        tk.Label(root, image=alb_img_tk, bg="white").place(x=20, y=10)
        tk.Label(root, text="Team ALBANIA", font=("Arial", 12, "bold"), fg="red", bg="white").place(x=25, y=115)

        ecsc_img = Image.open("./ecsc.png").resize((100, 100))
        ecsc_img_tk = ImageTk.PhotoImage(ecsc_img)
        tk.Label(root, image=ecsc_img_tk, bg="white").place(x=770, y=10)

        # kjo duhet rishikuar
        tk.Label(root, text="Flag Format (example: picoCTF)", bg="white").place(x=150, y=90)
        entry_flag = tk.Entry(root, width=50)
        entry_flag.place(x=150, y=115)

        tk.Label(root, text="Target File", bg="white").place(x=150, y=150)
        entry_file = tk.Entry(root, width=50)
        entry_file.place(x=150, y=175)
        tk.Button(root, text="Browse File", command=browse_file).place(x=500, y=172)

        open_pdf_var = tk.BooleanVar()
        tk.Checkbutton(root, text="Auto-open PDF Report", variable=open_pdf_var, bg="white").place(x=150, y=210)

        theme_var = tk.StringVar(value="light")
        tk.Checkbutton(root, text="Dark Theme", variable=theme_var, onvalue="dark", offvalue="light",
                       command=toggle_theme, bg="white").place(x=330, y=210)

        
        plugin_frame = tk.LabelFrame(root, text="Select Plugins", bg="white", padx=5, pady=5)
        plugin_frame.place(x=600, y=150, width=270, height=380)

        categories = {
            "Stego": [],
            "Metadata": [],
            "Office": [],
            "PDF": [],
            "Network": [],
            "Analysis": [],
            "ML / OCR / Image": []
        }

        for func in globals().values():
            if callable(func) and hasattr(func, "_plugin_name"):
                name = func._plugin_name
                lower = name.lower()
                if "pdf" in lower:
                    categories["PDF"].append(name)
                elif "office" in lower or "excel" in lower:
                    categories["Office"].append(name)
                elif "http" in lower or "tcp" in lower or "pcap" in lower:
                    categories["Network"].append(name)
                elif "ocr" in lower or "qr" in lower or "ml" in lower or "contrast" in lower:
                    categories["ML / OCR / Image"].append(name)
                elif "meta" in lower or "magic" in lower:
                    categories["Metadata"].append(name)
                elif "steg" in lower or "zsteg" in lower:
                    categories["Stego"].append(name)
                else:
                    categories["Analysis"].append(name)

        row = 0
        for cat, names in categories.items():
            tk.Label(plugin_frame, text=f"--- {cat} ---", bg="white", fg="blue", font=("Arial", 9, "bold")).grid(row=row, column=0, sticky="w")
            row += 1
            for name in names:
                plugin_vars[name] = tk.BooleanVar(value=True)
                chk = tk.Checkbutton(plugin_frame, text=name, variable=plugin_vars[name], bg="white")
                chk.grid(row=row, column=0, sticky="w")
                row += 1

        select_all_var = tk.BooleanVar(value=True)
        tk.Checkbutton(plugin_frame, text="Select All", variable=select_all_var,
                       command=toggle_all_plugins, bg="white", fg="green").grid(row=row, column=0, sticky="w")

        
        tk.Button(root, text="Start Analysis", command=start_analysis, bg="#4CAF50", fg="white", width=20).place(x=330, y=260)

        
        text_log = scrolledtext.ScrolledText(root, height=12, width=63, bg="white")
        text_log.place(x=20, y=360)

        loading_label = tk.Label(root, text="", bg="white", fg="blue", font=("Arial", 10, "italic"))
        loading_label.place(x=350, y=335)

        class PrintLogger:
            def write(self, txt):
                if "✓" in txt:
                    text_log.insert(tk.END, txt, "green")
                elif "!" in txt:
                    text_log.insert(tk.END, txt, "red")
                else:
                    text_log.insert(tk.END, txt)
                text_log.see(tk.END)
            def flush(self): pass

        text_log.tag_config("green", foreground="green")
        text_log.tag_config("red", foreground="red")
        sys.stdout = PrintLogger()
        sys.stderr = PrintLogger()

        root.mainloop()

    except ImportError:
        print(f"{RED}tkinter or Pillow not installed. GUI mode unavailable.{RESET}")




'''
@register_plugin
def ml_prioritize_files(_, __):                  #funksioni ka nevoj per ritrajnim dhe rikonsiderim
    import math
    from sklearn.tree import DecisionTreeClassifier
    import numpy as np

    info("Running ML-based artifact prioritization...")

    suspicious_samples = []
    clean_samples = []

    
    def randomness(name): return sum(1 for c in name if not c.isalnum()) / len(name)
    def mock_entropy(): return np.random.uniform(3.0, 8.0)
    def mock_size(): return np.random.randint(100, 50000)

    for _ in range(100):
        suspicious_samples.append([mock_entropy(), mock_size(), np.random.uniform(0.2, 1.0)])
        clean_samples.append([np.random.uniform(1.0, 5.0), np.random.randint(50000, 200000), np.random.uniform(0.0, 0.2)])

    X = suspicious_samples + clean_samples
    y = [1]*len(suspicious_samples) + [0]*len(clean_samples)

    clf = DecisionTreeClassifier(max_depth=4)
    clf.fit(X, y)

    
    paths = []
    for base in ["extract_here", "foremost_output", "_binwalk.extracted"]:
        if os.path.isdir(base):
            for root, _, files in os.walk(base):
                for name in files:
                    path = os.path.join(root, name)
                    paths.append(path)

    
    for path in paths:
        try:
            size = os.path.getsize(path)
            entropy_result = run_cmd(f"ent '{path}' 2>/dev/null")
            entropy_match = re.search(r'Entropy\s+=\s+([\d.]+)', entropy_result)
            entropy = float(entropy_match.group(1)) if entropy_match else 5.0
            randness = randomness(os.path.basename(path))

            features = [[entropy, size, randness]]
            pred = clf.predict_proba(features)[0][1]

            if pred > 0.5:
                pct = int(pred * 100)
                success(f"[ML] {path} → {pct}% suspicious (Entropy: {entropy:.2f}, Size: {size}, Name rand: {randness:.2f})")
        except Exception as e:
            warn(f"ML scan failed for {path}: {e}")
'''



def main():
    print_banner()
    if len(sys.argv) != 3:
        print(f"{YELLOW}Usage: python3 {sys.argv[0]} <flag_prefix> <filename>{RESET}")
        sys.exit(1)

    flag_prefix = sys.argv[1]
    filename = sys.argv[2]

    info(f"Searching for flag variants of: {flag_prefix}")
    variants = set()
    variants.add(flag_prefix)
    variants.add(flag_prefix[::-1])
    variants.add(base64.b64encode(flag_prefix.encode()).decode())
    variants.add(flag_prefix.encode().hex())
    variants.add(''.join(f"\\u{ord(c):04x}" for c in flag_prefix))
    variants.add(''.join(f"\\x{ord(c):02x}" for c in flag_prefix))

    analyze_output_for_flags("file type", run_cmd(f"file '{filename}'"), variants)
    binwalk_analysis(filename, variants)
    extract_with_foremost(filename, variants)
    entropy_analysis(filename, variants)
    metadata_analysis(filename, variants)
    document_analysis(filename, variants)
    run_volatility(filename, variants)
    analyze_pcap(filename, variants)
    extract_pcap_files_with_networkminer(filename)
    extract_http_files(filename, variants)
    reassemble_tcp_streams(filename, variants)
    unzip_recursive(filename, variants)
    zsteg_analysis(filename, variants)
    stegolsb_analysis(filename, variants)
    stepic_decode(filename, variants)
    xxd_analysis(filename, variants)

    detect_appended_data(filename, variants)
    analyze_png_chunks(filename, variants)
    analyze_jpeg_quantization(filename, variants)
    stegseek_crack(filename, "rockyou.txt", variants)
    extract_alpha_or_icc(filename, variants)
    analyze_magic_mismatch(filename, variants)
    scan_html_for_obfuscated_js(filename, variants)
    analyze_audio_video_stego(filename, variants)
    ocr_image_analysis(filename, variants)
    detect_qr_codes(filename, variants)
    enhance_contrast_sharpness(filename, variants)
    pdf_stego_detection(filename, variants)
    office_document_stego(filename, variants)
    detect_white_text_in_pdf(filename, variants)
    detect_hidden_formulas_in_office(filename, variants)
    detect_hidden_chart_alt_text(filename, variants)
    #ml_prioritize_files(_, __)

    generate_pdf_report(flag_prefix)

if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--gui":
        launch_gui()
    elif len(sys.argv) == 3:
        main()
    else:
        print(f"{YELLOW}Usage: python3 {sys.argv[0]} <flag_prefix> <filename> or --gui{RESET}")
        sys.exit(1)
