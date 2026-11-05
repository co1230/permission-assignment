"""
生成测试素材：Word / Excel / PDF / MP3 / MP4。

文本类素材（md、py、js）直接放在 test_files/ 里，其余由本脚本生成，方便复现：
    python tools/make_test_files.py
依赖：python-docx、openpyxl、imageio-ffmpeg（仅生成时用，服务本身不依赖它们）
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "test_files"
OUT.mkdir(exist_ok=True)


# --------------------------------------------------------------------------- #
# Word
# --------------------------------------------------------------------------- #
def make_docx(path: Path) -> None:
    from docx import Document
    from docx.shared import Pt

    doc = Document()
    doc.add_heading("项目启动会会议纪要", level=0)
    doc.add_paragraph("时间：2026 年 11 月 5 日 14:30　地点：三楼小会议室").italic = True

    doc.add_heading("一、背景", level=1)
    doc.add_paragraph(
        "本次讨论围绕「文件加密与权限隔离」展开。核心诉求是：不同角色拥有不同的解密能力，"
        "而系统的搭建者本身也不能解密任何文件。"
    )

    doc.add_heading("二、角色分工", level=1)
    table = doc.add_table(rows=4, cols=3)
    table.style = "Light Grid Accent 1"
    rows = [
        ("角色", "职责", "解密权限"),
        ("小孔", "普通用户，负责提交与加密文件", "无"),
        ("小张", "部门领导，负责查看文件内容", "有"),
        ("搭建者", "部署与运维系统", "无（硬性要求）"),
    ]
    for row, values in zip(table.rows, rows):
        for cell, value in zip(row.cells, values):
            cell.text = value

    doc.add_heading("三、结论", level=1)
    doc.add_paragraph("1. 对照版（V1）用于说明「服务端持钥」的常规做法及其风险。")
    doc.add_paragraph("2. 目标版（V2）采用信封加密：私钥只在有权限的人手里，服务端只存密文。")
    doc.add_paragraph("3. 下周演示两个版本，并用 Markdown、代码、音频、视频四类文件验证效果。")
    doc.add_paragraph("")
    p = doc.add_paragraph("记录人：项目组")
    p.runs[0].font.size = Pt(9)

    doc.save(path)


# --------------------------------------------------------------------------- #
# Excel
# --------------------------------------------------------------------------- #
def make_xlsx(path: Path) -> None:
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill

    wb = Workbook()
    ws = wb.active
    ws.title = "权限矩阵"

    headers = ["角色", "上传/加密", "下载密文", "解密", "持有密钥", "备注"]
    ws.append(headers)
    data = [
        ("小孔", "可以", "不可（V2）", "不可", "无", "普通用户，只负责加密"),
        ("小张", "可以", "可以", "可以", "有（私钥在本机）", "领导，唯一可解密角色"),
        ("搭建者", "可以", "可以", "不可", "无", "能拿到服务器与数据库，仍解不开"),
    ]
    for row in data:
        ws.append(row)

    ws2 = wb.create_sheet("测试文件清单")
    ws2.append(["文件名", "类型", "大小(KB)", "加密后是否可还原"])
    for name in ["项目说明.md", "demo_code.py", "demo_code.js", "会议纪要.docx",
                 "数据统计.xlsx", "演示报告.pdf", "测试音频.mp3", "演示视频.mp4"]:
        candidate = OUT / name
        size = round(candidate.stat().st_size / 1024, 1) if candidate.exists() else 0
        ws2.append([name, candidate.suffix.lstrip("."), size, "待验证"])

    header_fill = PatternFill("solid", fgColor="0F766E")
    for sheet in (ws, ws2):
        for cell in sheet[1]:
            cell.font = Font(bold=True, color="FFFFFF")
            cell.fill = header_fill
            cell.alignment = Alignment(horizontal="center")
        for column in sheet.columns:
            width = max(len(str(c.value or "")) for c in column) * 1.9 + 4
            sheet.column_dimensions[column[0].column_letter].width = min(max(width, 10), 34)

    wb.save(path)


# --------------------------------------------------------------------------- #
# PDF（手写最小 PDF，避免额外依赖）
# --------------------------------------------------------------------------- #
def make_pdf(path: Path) -> None:
    lines = [
        ("Helvetica-Bold", 20, "File Encryption Demo Report"),
        ("Helvetica", 11, "Generated for the permission-isolation demo."),
        ("Helvetica", 11, "This PDF is a binary test sample: if encryption"),
        ("Helvetica", 11, "corrupts a single byte, the file will not open."),
        ("Helvetica", 11, ""),
        ("Helvetica-Bold", 13, "Roles"),
        ("Helvetica", 11, "Xiao Kong  - encrypt only, no decryption rights"),
        ("Helvetica", 11, "Xiao Zhang - holds the private key, can decrypt"),
        ("Helvetica", 11, "Builder    - owns the server, cannot decrypt (V2)"),
        ("Helvetica", 11, ""),
        ("Helvetica-Bold", 13, "Algorithms"),
        ("Helvetica", 11, "AES-256-GCM for file content"),
        ("Helvetica", 11, "RSA-OAEP-2048 (SHA-256) for key wrapping"),
        ("Helvetica", 11, "PBKDF2-SHA256 250000 iterations for the key package"),
        ("Helvetica", 11, ""),
        ("Helvetica", 10, "SHA-256 of the original file should match after decryption."),
    ]

    content = ["BT", "72 780 Td", "14 TL"]
    for font, size, text in lines:
        escaped = text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")
        content.append(f"/{ 'F2' if 'Bold' in font else 'F1' } {size} Tf")
        content.append(f"({escaped}) Tj T*")
    content.append("ET")
    stream = "\n".join(content).encode("latin-1")

    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
        b"/Resources << /Font << /F1 4 0 R /F2 5 0 R >> >> /Contents 6 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
    ]

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for index, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{index} 0 obj\n".encode() + body + b"\nendobj\n"

    xref_at = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for offset in offsets[1:]:
        out += f"{offset:010d} 00000 n \n".encode()
    out += (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n".encode()
    )
    path.write_bytes(bytes(out))


# --------------------------------------------------------------------------- #
# 音频 / 视频（ffmpeg 来自 imageio-ffmpeg，仅生成阶段使用）
# --------------------------------------------------------------------------- #
def ffmpeg() -> str:
    import imageio_ffmpeg

    return imageio_ffmpeg.get_ffmpeg_exe()


def make_mp3(path: Path) -> None:
    """先用纯 Python 合成一段琶音 WAV，再交给 ffmpeg 编码成 MP3（含 ID3 元数据）。"""
    import math
    import struct
    import tempfile
    import wave

    rate = 44100
    notes = [523.25, 659.25, 783.99, 1046.50, 783.99, 659.25]  # C5 E5 G5 C6 G5 E5
    note_len = 0.5
    samples = []
    for index in range(2):
        for freq in notes:
            count = int(rate * note_len)
            for i in range(count):
                t = i / rate
                envelope = math.exp(-3.2 * t) * (1 - math.exp(-400 * t))
                value = 0.34 * envelope * math.sin(2 * math.pi * freq * t)
                value += 0.10 * envelope * math.sin(2 * math.pi * freq * 2 * t)
                samples.append(value)
    # 尾部淡出，避免爆音
    tail = int(rate * 0.3)
    samples.extend([0.0] * tail)

    with tempfile.TemporaryDirectory() as tmp:
        wav_path = Path(tmp) / "tone.wav"
        with wave.open(str(wav_path), "wb") as wav:
            wav.setnchannels(1)
            wav.setsampwidth(2)
            wav.setframerate(rate)
            frames = bytearray()
            for value in samples:
                clipped = max(-1.0, min(1.0, value))
                frames += struct.pack("<h", int(clipped * 32767))
            wav.writeframes(bytes(frames))

        cmd = [
            ffmpeg(), "-y", "-hide_banner", "-loglevel", "error",
            "-i", str(wav_path),
            "-ac", "2", "-c:a", "libmp3lame", "-b:a", "128k",
            "-metadata", "title=加密演示测试音频",
            "-metadata", "artist=权限隔离项目组",
            "-metadata", "comment=用于验证二进制音频文件的加解密完整性",
            str(path),
        ]
        subprocess.run(cmd, check=True)


def make_mp4(path: Path) -> None:
    cmd = [
        ffmpeg(), "-y", "-hide_banner", "-loglevel", "error",
        "-f", "lavfi", "-i", "testsrc2=size=1280x720:rate=30:duration=6",
        "-f", "lavfi", "-i", "sine=frequency=440:duration=6",
        "-c:v", "libx264", "-preset", "medium", "-crf", "26", "-pix_fmt", "yuv420p",
        "-c:a", "aac", "-b:a", "96k", "-shortest",
        "-movflags", "+faststart",
        "-metadata", "title=加密演示测试视频",
        str(path),
    ]
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError:
        cmd[cmd.index("libx264")] = "mpeg4"
        subprocess.run(cmd, check=True)


def main() -> None:
    targets = [
        (OUT / "会议纪要.docx", make_docx),
        (OUT / "数据统计.xlsx", make_xlsx),
        (OUT / "演示报告.pdf", make_pdf),
        (OUT / "测试音频.mp3", make_mp3),
        (OUT / "演示视频.mp4", make_mp4),
    ]
    for path, builder in targets:
        builder(path)
        print(f"生成 {path.name:16s} {path.stat().st_size / 1024:8.1f} KB")
    print("完成。")


if __name__ == "__main__":
    sys.exit(main())
