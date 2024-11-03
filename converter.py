import pefile
import sys
import os

def inject_code(pe, code_bytes):
    # Calculate the new offset for the injected code
    new_section_offset = pe.sections[-1].PointerToRawData + pe.sections[-1].SizeOfRawData
    pe.set_bytes_at_offset(new_section_offset, code_bytes)
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = new_section_offset - pe.OPTIONAL_HEADER.ImageBase
    return pe

def exe_to_dll(file_path, dll_code_path):
    try:
        pe = pefile.PE(file_path)
        if pe.OPTIONAL_HEADER.Subsystem != 2:
            print("This file is not a valid executable.")
            return

        with open(dll_code_path, "rb") as f:
            code_bytes = f.read()

        print("Converting EXE to DLL and injecting DllMain...")
        pe.OPTIONAL_HEADER.Subsystem = 2
        pe.FILE_HEADER.Characteristics |= 0x2000
        pe = inject_code(pe, code_bytes)
        new_file_path = file_path.replace(".exe", ".dll")
        pe.write(new_file_path)
        print(f"Conversion complete! Saved as {new_file_path}")
    except Exception as e:
        print(f"Error converting EXE to DLL: {e}")

def dll_to_exe(file_path, exe_code_path):
    try:
        pe = pefile.PE(file_path)
        if not (pe.FILE_HEADER.Characteristics & 0x2000):
            print("This file is not a valid DLL.")
            return

        with open(exe_code_path, "rb") as f:
            code_bytes = f.read()

        print("Converting DLL to EXE and injecting main...")
        pe.FILE_HEADER.Characteristics &= ~0x2000
        pe = inject_code(pe, code_bytes)
        new_file_path = file_path.replace(".dll", ".exe")
        pe.write(new_file_path)
        print(f"Conversion complete! Saved as {new_file_path}")
    except Exception as e:
        print(f"Error converting DLL to EXE: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python converter.py [exe_to_dll | dll_to_exe] <file_path> <code_path>")
        sys.exit(1)
    
    action = sys.argv[1]
    file_path = sys.argv[2]
    code_path = sys.argv[3]

    if not os.path.isfile(file_path):
        print("File does not exist.")
        sys.exit(1)

    if action == "exe_to_dll":
        exe_to_dll(file_path, code_path)
    elif action == "dll_to_exe":
        dll_to_exe(file_path, code_path)
    else:
        print("Invalid action. Use 'exe_to_dll' or 'dll_to_exe'.")
