"""S-AES teaching desktop app; Python standard library only."""
import threading
import tkinter as tk
from tkinter import messagebox, ttk
from saes import (encrypt_block, decrypt_block, double_encrypt, double_decrypt,
                  triple_encrypt, triple_decrypt, mitm_attack, encrypt_ascii,
                  decrypt_ascii, cbc_encrypt, cbc_decrypt)


def read_hex(value: str, digits: int, name: str) -> int:
    text = value.strip().replace(" ", "")
    if len(text) != digits or any(char not in "0123456789abcdefABCDEF" for char in text):
        raise ValueError(f"{name}必须是 {digits} 位十六进制数")
    return int(text, 16)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("S-AES 实验平台")
        self.geometry("760x600")
        self.minsize(680, 520)
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=12, pady=12)
        for title, builder in (("单块 / 多重", self.build_blocks),
                               ("ASCII 文本", self.build_ascii),
                               ("中间相遇", self.build_mitm),
                               ("CBC 模式", self.build_cbc)):
            frame = ttk.Frame(notebook, padding=16)
            notebook.add(frame, text=title)
            builder(frame)

    def field(self, parent, row, label, initial=""):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=5)
        variable = tk.StringVar(value=initial)
        ttk.Entry(parent, textvariable=variable, width=62).grid(row=row, column=1, sticky="ew", padx=8)
        parent.columnconfigure(1, weight=1)
        return variable

    def run_safe(self, action):
        try:
            action()
        except (ValueError, UnicodeError) as error:
            messagebox.showerror("输入错误", str(error))

    def build_blocks(self, frame):
        mode = self.field(frame, 0, "模式", "S-AES")
        ttk.Label(frame, text="模式填写 S-AES、Double 或 Triple；Triple 使用 48 位 EEE。") .grid(row=1, column=1, sticky="w")
        source = self.field(frame, 2, "输入分组 Hex (4 位)", "D728")
        key = self.field(frame, 3, "密钥 Hex (4/8/12 位)", "4AF5")
        output = self.field(frame, 5, "输出分组 Hex")

        def process(decrypt):
            chosen = mode.get().strip().lower()
            actions = {"s-aes": (4, encrypt_block, decrypt_block),
                       "double": (8, double_encrypt, double_decrypt),
                       "triple": (12, triple_encrypt, triple_decrypt)}
            if chosen not in actions:
                raise ValueError("模式必须是 S-AES、Double 或 Triple")
            digits, enc, dec = actions[chosen]
            output.set(f"{(dec if decrypt else enc)(read_hex(source.get(), 4, '分组'), read_hex(key.get(), digits, '密钥')):04X}")

        bar = ttk.Frame(frame)
        bar.grid(row=4, column=1, sticky="w", pady=10)
        ttk.Button(bar, text="加密", command=lambda: self.run_safe(lambda: process(False))).pack(side="left", padx=4)
        ttk.Button(bar, text="解密", command=lambda: self.run_safe(lambda: process(True))).pack(side="left", padx=4)

    def build_ascii(self, frame):
        ttk.Label(frame, text="ASCII 每 2 字节一组；使用 PKCS#7 填充；密文以 Hex 传输。") .grid(row=0, column=1, sticky="w")
        key = self.field(frame, 1, "16 位密钥 Hex", "4AF5")
        plain = self.field(frame, 2, "ASCII 明文", "HELLO")
        cipher = self.field(frame, 3, "密文 Hex")
        restored = self.field(frame, 5, "解密结果")
        bar = ttk.Frame(frame)
        bar.grid(row=4, column=1, sticky="w", pady=10)
        ttk.Button(bar, text="加密", command=lambda: self.run_safe(lambda: cipher.set(encrypt_ascii(plain.get(), read_hex(key.get(), 4, '密钥'))))).pack(side="left", padx=4)
        ttk.Button(bar, text="解密", command=lambda: self.run_safe(lambda: restored.set(decrypt_ascii(cipher.get(), read_hex(key.get(), 4, '密钥'))))).pack(side="left", padx=4)

    def build_mitm(self, frame):
        ttk.Label(frame, text="每行一组：4位明文Hex 空格 4位密文Hex；至少两组可明显缩小候选集合。") .pack(anchor="w")
        input_box = tk.Text(frame, height=8)
        input_box.pack(fill="x", pady=8)
        input_box.insert("1.0", "D728 0000\n")
        result = tk.Text(frame, height=14, state="disabled")
        result.pack(fill="both", expand=True, pady=8)

        def show(message):
            result.configure(state="normal")
            result.delete("1.0", "end")
            result.insert("1.0", message)
            result.configure(state="disabled")

        def start():
            try:
                pairs = []
                for line in input_box.get("1.0", "end").splitlines():
                    if line.strip():
                        parts = line.split()
                        if len(parts) != 2:
                            raise ValueError("每行必须恰好有明文和密文两项")
                        pairs.append((read_hex(parts[0], 4, "明文"), read_hex(parts[1], 4, "密文")))
                if not pairs:
                    raise ValueError("至少输入一组明密文")
            except ValueError as error:
                messagebox.showerror("输入错误", str(error))
                return
            show("搜索中，请稍候…")

            def worker():
                candidates = mitm_attack(pairs)
                preview = "\n".join(f"{value:08X}" for value in candidates[:100])
                note = "\n仅显示前 100 项" if len(candidates) > 100 else ""
                self.after(0, lambda: show(f"符合全部 {len(pairs)} 组的候选密钥：{len(candidates)} 个\n{preview}{note}"))

            threading.Thread(target=worker, daemon=True).start()

        ttk.Button(frame, text="开始中间相遇搜索", command=start).pack(anchor="w")

    def build_cbc(self, frame):
        ttk.Label(frame, text="UTF-8 文本；IV 随机生成，也可指定用于复现；密文以 Hex 传输。") .grid(row=0, column=1, sticky="w")
        key = self.field(frame, 1, "16 位密钥 Hex", "4AF5")
        iv = self.field(frame, 2, "IV Hex (加密可留空)")
        plain = self.field(frame, 3, "明文", "CBC mode demo")
        cipher = self.field(frame, 4, "密文 Hex")
        restored = self.field(frame, 6, "解密结果")

        def encrypt():
            iv_value, encrypted = cbc_encrypt(plain.get().encode("utf-8"), read_hex(key.get(), 4, "密钥"),
                                              read_hex(iv.get(), 4, "IV") if iv.get().strip() else None)
            iv.set(f"{iv_value:04X}")
            cipher.set(encrypted.hex().upper())

        def decrypt():
            restored.set(cbc_decrypt(bytes.fromhex(cipher.get()), read_hex(key.get(), 4, "密钥"),
                                     read_hex(iv.get(), 4, "IV")).decode("utf-8"))

        bar = ttk.Frame(frame)
        bar.grid(row=5, column=1, sticky="w", pady=10)
        ttk.Button(bar, text="加密", command=lambda: self.run_safe(encrypt)).pack(side="left", padx=4)
        ttk.Button(bar, text="解密", command=lambda: self.run_safe(decrypt)).pack(side="left", padx=4)


if __name__ == "__main__":
    App().mainloop()
