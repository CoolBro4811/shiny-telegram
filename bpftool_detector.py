import subprocess
import json

def detect_ebpf_hooks():
    # List all loaded eBPF programs
    result = subprocess.run(['bpftool', 'prog', 'list', '-j'], 
                           capture_output=True, text=True)
    progs = json.loads(result.stdout)
    
    suspicious = []
    for prog in progs:
        # Check for attached tracepoints that shouldn't be there
        if 'tracepoint' in prog.get('attached', ''):
            if prog['name'] in ['hide_getdents', 'hide_proc', 'stealth']:
                suspicious.append(prog)
    
    # Check pinned programs (persistence mechanism)
    result = subprocess.run(['find', '/sys/fs/bpf', '-type', 'f'], 
                           capture_output=True, text=True)
    pins = result.stdout.splitlines()
    
    return suspicious, pins

def verify_syscall_integrity():
    # Compare syscall table against known-good kernel image
    # This requires kernel debug symbols
    result = subprocess.run(['cat', '/proc/kallsyms'], 
                           capture_output=True, text=True)
    
    # Look for syscall entries pointing to non-kernel text sections
    # Suspicious addresses are those not in the kernel's .text range
    return result.stdout
