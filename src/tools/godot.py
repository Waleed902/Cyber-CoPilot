"""
Godot Engine Reverse Engineering Tools
Provides tools for extracting .pck archives and decompiling GDScript bytecode.
"""

import os
import struct
import subprocess
import shutil
from src.sdk.tool import function_tool

@function_tool()
def godot_pck_extract(pck_path: str, output_dir: str | None = None) -> str:
    """
    Extract files from a Godot .pck archive.
    Use this immediately when you identify a Godot project to see the game source code.
    
    Args:
        pck_path: Path to the .pck file (usually found in the game directory)
        output_dir: Optional output directory (default: _<filename>.pck_out)
        
    Returns:
        Status message and list of extracted files
    """
    from src.tools.forensics import _convert_to_linux_path, smart_output
    
    pck_path = _convert_to_linux_path(pck_path)
    if not os.path.exists(pck_path):
        return f"Error: File '{pck_path}' not found."
        
    if not output_dir:
        output_dir = os.path.join(os.path.dirname(pck_path), f"_{os.path.basename(pck_path)}_out")
    
    os.makedirs(output_dir, exist_ok=True)
    
    # Try using a dedicated tool if available
    godot_pck_tool = shutil.which("godot-pck-extract")
    if godot_pck_tool:
        try:
            result = subprocess.run(
                [godot_pck_tool, pck_path, "-o", output_dir],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0:
                files = os.listdir(output_dir)
                return f"[SUCCESS] Extracted {len(files)} files to {output_dir}\n{result.stdout}"
        except Exception:
            pass

    # Fallback: Basic Python-based extraction for GDPC format
    try:
        with open(pck_path, "rb") as f:
            magic = f.read(4)
            if magic != b"GDPC":
                return f"Error: Not a valid Godot PCK file (Magic: {magic.hex()})"
            
            # Read version info
            struct.unpack("<I", f.read(4))[0]
            struct.unpack("<I", f.read(4))[0]
            struct.unpack("<I", f.read(4))[0]
            struct.unpack("<I", f.read(4))[0]
            
            # Skip reserved / flags
            f.read(64) 
            
            file_count = struct.unpack("<I", f.read(4))[0]
            
            extracted = []
            for _ in range(file_count):
                path_len = struct.unpack("<I", f.read(4))[0]
                path = f.read(path_len).decode("utf-8").replace("res://", "")
                offset = struct.unpack("<Q", f.read(8))[0]
                size = struct.unpack("<Q", f.read(8))[0]
                # MD5 hash (16 bytes)
                f.read(16)
                
                # Save current position
                cur_pos = f.tell()
                
                # Seek and extract
                f.seek(offset)
                data = f.read(size)
                
                out_path = os.path.join(output_dir, path)
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                with open(out_path, "wb") as out_f:
                    out_f.write(data)
                
                extracted.append(path)
                
                # Return to index
                f.seek(cur_pos)
            
            summary = f"[SUCCESS] Extracted {len(extracted)} files to {output_dir}\n"
            summary += "\n".join(extracted[:20])
            if len(extracted) > 20:
                summary += f"\n... and {len(extracted)-20} more."
                
            return smart_output(summary, "godot_pck_extract", os.path.basename(pck_path))
            
    except Exception as e:
        return f"Error during manual extraction: {str(e)}"

@function_tool()
def godot_gds_decompile(gdc_path: str) -> str:
    """
    Decompile a Godot .gdc (compiled GDScript) file to human-readable GDScript.
    Use this on any .gdc files found inside an extracted .pck to understand the game logic.
    
    Args:
        gdc_path: Path to the compiled .gdc file
        
    Returns:
        Decompiled GDScript source code (or helpful tips if decompiler is missing)
    """
    from src.tools.forensics import _convert_to_linux_path
    
    gdc_path = _convert_to_linux_path(gdc_path)
    if not os.path.exists(gdc_path):
        return f"Error: File '{gdc_path}' not found."
        
    # Heuristic: Check if it's a GDC file (magic: 'GDSC' or just starts with specific sequence)
    with open(gdc_path, "rb") as f:
        magic = f.read(4)
        # GDC files often start with 0x47 0x44 0x53 0x43 (GDSC) or similar
        
    # Try using gdsdecomp if available
    gdsdecomp = shutil.which("gdsdecomp")
    if gdsdecomp:
        try:
            result = subprocess.run(
                [gdsdecomp, "--decompile", gdc_path],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                return result.stdout
        except Exception:
            pass
            
    return (
        f"[NOTICE] Specialized Godot decompiler not found in environment.\n"
        f"Magic detected: {magic.hex()}\n"
        f"Technique Tip: Try strings {gdc_path} to see function names and constants, "
        f"or use a custom script to parse GDScript bytecode."
    )
