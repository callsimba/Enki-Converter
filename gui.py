import ctypes
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image, ImageTk
import pefile
import os

try:
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
except Exception:
    pass

def inject_code(pe, code_bytes):
    new_section_offset = pe.sections[-1].PointerToRawData + pe.sections[-1].SizeOfRawData
    pe.set_bytes_at_offset(new_section_offset, code_bytes)
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = new_section_offset - pe.OPTIONAL_HEADER.ImageBase
    return pe

def exe_to_dll(file_path, dll_code_path=None):
    try:
        pe = pefile.PE(file_path)
        if pe.OPTIONAL_HEADER.Subsystem != 2:
            messagebox.showerror("Error", "This file is not a valid executable.")
            return
        if dll_code_path: 
            with open(dll_code_path, "rb") as f:
                code_bytes = f.read()
            pe = inject_code(pe, code_bytes)
        pe.OPTIONAL_HEADER.Subsystem = 2
        pe.FILE_HEADER.Characteristics |= 0x2000
        new_file_path = file_path.replace(".exe", ".dll")
        pe.write(new_file_path)
        messagebox.showinfo("Success", f"Conversion complete! Saved as {new_file_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Error converting EXE to DLL: {e}")

def dll_to_exe(file_path, exe_code_path=None):
    try:
        pe = pefile.PE(file_path)
        if not (pe.FILE_HEADER.Characteristics & 0x2000):
            messagebox.showerror("Error", "This file is not a valid DLL.")
            return
        if exe_code_path:
            with open(exe_code_path, "rb") as f:
                code_bytes = f.read()
            pe = inject_code(pe, code_bytes)
        pe.FILE_HEADER.Characteristics &= ~0x2000
        new_file_path = file_path.replace(".dll", ".exe")
        pe.write(new_file_path)
        messagebox.showinfo("Success", f"Conversion complete! Saved as {new_file_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Error converting DLL to EXE: {e}")

def select_file():
    file_path = filedialog.askopenfilename(title="Select a file", filetypes=[("Executable and DLL files", "*.exe *.dll")])
    if file_path:
        entry_file.delete(0, tk.END)
        entry_file.insert(0, file_path)

def select_code_file():
    code_file_path = filedialog.askopenfilename(title="Select code file", filetypes=[("Object files", "*.o *.obj")])
    if code_file_path:
        entry_code_file.delete(0, tk.END)
        entry_code_file.insert(0, code_file_path)

def convert():
    file_path = entry_file.get()
    code_file_path = entry_code_file.get() if entry_code_file.get() else None
    action = var.get()
    
    if not file_path:
        messagebox.showerror("Error", "Please select a file to convert.")
        return

    if action == "exe_to_dll":
        exe_to_dll(file_path, code_file_path)
    elif action == "dll_to_exe":
        dll_to_exe(file_path, code_file_path)

app = tk.Tk()
app.title("Enki Converter")
app.geometry("900x700")
app.config(bg="#CC313D")
app.iconbitmap(r"C:\Users\Enki\Desktop\ExeDllConverter\icon.ico")

style = ttk.Style()
style.configure("TNotebook", background="gray")
style.configure("TNotebook.Tab", background="gray", padding=[10, 5])
style.map("TNotebook.Tab", background=[("selected", "gray")])

notebook = ttk.Notebook(app, style="TNotebook")
notebook.pack(pady=10, expand=True)

style.configure("TFrame", background="#CC313D")
style.configure("TLabel", background="#CC313D", foreground="white", font=("Segoe UI", 12, "bold"))
style.configure("TButton", background="gray", foreground="black", font=("Segoe UI", 12, "bold"))
style.configure("TRadiobutton", background="#CC313D", foreground="white", font=("Segoe UI", 12, "bold"))

logo_frame = tk.Frame(app, bg="#CC313D")
logo_frame.pack()
logo_image = Image.open(r"C:\Users\Enki\Desktop\ExeDllConverter\logo.png")
logo_image = logo_image.resize((100, 33), Image.LANCZOS)
logo_photo = ImageTk.PhotoImage(logo_image)
logo_label = tk.Label(logo_frame, image=logo_photo, bg="#CC313D")
logo_label.pack()

conversion_tab = ttk.Frame(notebook, style="TFrame")

label_file = ttk.Label(conversion_tab, text="Select File to Convert:")
label_file.grid(row=0, column=0, padx=5, pady=5, sticky="w")
entry_file = tk.Entry(conversion_tab, width=30)
entry_file.grid(row=0, column=1, padx=5, pady=5)
button_browse_file = ttk.Button(conversion_tab, text="Browse", command=select_file)
button_browse_file.grid(row=0, column=2, padx=5, pady=5)

label_code_file = ttk.Label(conversion_tab, text="Select Code File (.o/.obj) [Optional]:")
label_code_file.grid(row=1, column=0, padx=5, pady=5, sticky="w")
entry_code_file = tk.Entry(conversion_tab, width=30)
entry_code_file.grid(row=1, column=1, padx=5, pady=5)
button_browse_code_file = ttk.Button(conversion_tab, text="Browse", command=select_code_file)
button_browse_code_file.grid(row=1, column=2, padx=5, pady=5)

var = tk.StringVar(value="exe_to_dll")
radio_exe_to_dll = ttk.Radiobutton(conversion_tab, text="EXE to DLL", variable=var, value="exe_to_dll")
radio_exe_to_dll.grid(row=2, column=0, pady=10, sticky="w")
radio_dll_to_exe = ttk.Radiobutton(conversion_tab, text="DLL to EXE", variable=var, value="dll_to_exe")
radio_dll_to_exe.grid(row=2, column=1, pady=10, sticky="w")

button_convert = ttk.Button(conversion_tab, text="Convert", command=convert, width=20)
button_convert.grid(row=3, column=0, columnspan=3, pady=20)

notebook.add(conversion_tab, text="Enki Converter")

about_tab = ttk.Frame(notebook, style="TFrame")
about_label = ttk.Label(
    about_tab,
    text=(
        "Enki Converter\n\n"
        "A standalone tool designed to seamlessly convert .EXE files to .DLL and vice versa. "
        "Enki Converter simplifies the conversion process, ensuring efficiency and reliability for developers.\n\n"
        "For questions, suggestions, or customization requests, feel free to reach out:\n"
        "Telegram: @npx_react_native\n"
        "GitHub: github.com/callsimba"
    ),
    justify="center",
    wraplength=500
)
about_label.pack(pady=30)
notebook.add(about_tab, text="About Converter")

app.mainloop()
