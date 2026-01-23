#!/usr/bin/env python3
"""
Kernel Patcher for Bruteforce Tool
Based on patches from iphone-dataprotection project
Covers iOS 4, 5, 6 and ARMv6 devices
"""
import sys
import pathlib
import argparse

def patch_kernel(input_path: pathlib.Path, target_os: str, target_arch: str):
    try:
        with open(input_path, "rb") as f:
            data = bytearray(f.read())
    except Exception as e:
        print(f"Error reading {input_path}: {e}")
        return False

    # Patch Definitions
    patches_map = {
        "6": [
            ("IOAESAccelerator enable UID (iOS 6)", 
             bytes.fromhex("B0 F5 FA 6F 00 F0 92 80"), 
             bytes.fromhex("B0 F5 FA 6F 00 20 00 20")),
            ("_PE_i_can_has_debugger (iOS 6)", 
             bytes.fromhex("80 B1 43 F2 BE 01 C0 F2"), 
             bytes.fromhex("01 20 70 47 BE 01 C0 F2")),
            ("panic(AppleNANDFTL) (iOS 6)", 
             bytes.fromhex("05 46 4D B9 58 48 78 44 0A F0 28 FE"), 
             bytes.fromhex("05 46 4D B9 58 48 78 44 00 20 00 20")),
            ("AppleIOPFMI::_fmiPatchMetaFringe (PPN)", 
             bytes.fromhex("F0 B5 03 AF 81 B0 1C 46 15 46 0E 46 B5 42"), 
             bytes.fromhex("70 47 03 AF 81 B0 1C 46 15 46 0E 46 B5 42")),
        ],
        "5": [
            ("CSED (iOS 5)", 
             bytes.fromhex("df f8 88 33 1d ee 90 0f a2 6a 1b 68"), 
             bytes.fromhex("df f8 88 33 1d ee 90 0f a2 6a 01 23")),
            ("AMFI (iOS 5)", 
             bytes.fromhex("D0 47 01 21 40 B1 13 35"), 
             bytes.fromhex("00 20 01 21 40 B1 13 35")),
            ("_PE_i_can_has_debugger (iOS 5)", 
             bytes.fromhex("38 B1 05 49 09 68 00 29"), 
             bytes.fromhex("01 20 70 47 09 68 00 29")),
            ("task_for_pid_0 (iOS 5)", 
             bytes.fromhex("00 21 02 91 ba f1 00 0f 01 91 06 d1 02 a8"), 
             bytes.fromhex("00 21 02 91 ba f1 00 0f 01 91 06 e0 02 a8")),
            ("IOAESAccelerator enable UID (iOS 5)", 
             bytes.fromhex("67 D0 40 F6"), 
             bytes.fromhex("00 20 40 F6")),
            ("IOAES gid (iOS 5)", 
             bytes.fromhex("40 46 D4 F8 54 43 A0 47"), 
             bytes.fromhex("40 46 D4 F8 43 A0 00 20")),
        ],
        "4": [
            ("NAND_epoch (iOS 4)", 
             b"\x90\x47\x83\x45", 
             b"\x90\x47\x00\x20"),
            ("AMFI (iOS 4)", 
             b"\x01\xD1\x01\x30\x04\xE0\x02\xDB", 
             b"\x00\x20\x01\x30\x04\xE0\x02\xDB"),
            ("IOAESAccelerator enable UID (iOS 4)", 
             b"\x56\xD0\x40\xF6", 
             b"\x00\x00\x40\xF6"),
            ("_PE_i_can_has_debugger (iOS 4)", 
             bytes.fromhex("48 B1 06 4A 13 68 13 B9"), 
             bytes.fromhex("01 20 70 47 13 68 13 B9")),
        ],
        "armv6": [
            ("NAND_epoch (ARMv6)", 
             bytes.fromhex("00 00 5B E1 0E 00 00 0A"), 
             bytes.fromhex("00 00 5B E1 0E 00 00 EA")),
            ("CSED (ARMv6)", 
             bytes.fromhex("00 00 00 00 01 00 00 00 80 00 00 00 00 00 00 00"), 
             bytes.fromhex("01 00 00 00 01 00 00 00 80 00 00 00 00 00 00 00")),
             ("AMFI (ARMv6)", 
              bytes.fromhex("00 00 00 0A 00 40 A0 E3 04 00 A0 E1 90 80 BD E8"), 
              bytes.fromhex("00 00 00 0A 00 40 A0 E3 01 00 A0 E3 90 80 BD E8")),
            ("_PE_i_can_has_debugger (ARMv6)", 
             bytes.fromhex("00 28 0B D0 07 4A 13 68 00 2B 02 D1 03 60 10 68"), 
             bytes.fromhex("01 20 70 47 07 4A 13 68 00 2B 02 D1 03 60 10 68")),
            ("IOAESAccelerator enable UID (ARMv6)", 
             bytes.fromhex("5D D0 36 4B 9A 42"), 
             bytes.fromhex("00 20 36 4B 9A 42")),
            ("IOAES gid (ARMv6)", 
             bytes.fromhex("FA 23 9B 00 9A 42 05 D1"), 
             bytes.fromhex("00 20 00 20 9A 42 05 D1")),
        ]
    }

    selected_patches = []
    
    if target_arch == "armv6":
        print("Mode: ARMv6")
        selected_patches = patches_map["armv6"]
    else:
        print(f"Mode: iOS {target_os}")
        if target_os in patches_map:
            selected_patches = patches_map[target_os]
        else:
            print(f"Warning: No specific patches for iOS {target_os}. Using iOS 6 as fallback.")
            selected_patches = patches_map.get("6", [])
            
            # For unknown versions, maybe we should try iOS 5/4 signatures too if they don't conflict?
            # But that caused the original issue. Safer to stick to one set.

    patched_count = 0
    
    for name, pattern, replacement in selected_patches:
        count = data.count(pattern)
        if count > 0:
            print(f"Applying patch: {name} (Found {count} times)")
            data = data.replace(pattern, replacement)
            patched_count += 1
    
    output_path = input_path.with_suffix(".patched")
    try:
        with open(output_path, "wb") as f:
            f.write(data)
    except Exception as e:
        print(f"Error writing {output_path}: {e}")
        return False
    
    if patched_count > 0:
        print(f"Kernel patched successfully ({patched_count} patches applied). Saved to {output_path}")
        return True
    else:
        print("No patches applied (no patterns found in selected set).")
        # Ensure we still create the output file
        with open(output_path, "wb") as f:
            f.write(data)
        return True

def main():
    parser = argparse.ArgumentParser(description="Kernel Patcher")
    parser.add_argument("file", help="Input kernel file")
    parser.add_argument("--os", help="Target iOS major version (4, 5, 6, 9)", default="6")
    parser.add_argument("--arch", help="Target architecture (armv6, armv7)", default="armv7")
    
    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)
        
    args = parser.parse_args()
    
    path = pathlib.Path(args.file)
    if not path.exists():
        print(f"File not found: {args.file}")
        sys.exit(1)
        
    if not patch_kernel(path, args.os, args.arch):
        sys.exit(1)

if __name__ == "__main__":
    main()
