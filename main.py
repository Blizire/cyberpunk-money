import psutil
import win32process
import win32api
import ctypes

PROCESS_ALL_ACCESS = 0x1F0FFF

def get_pid(process_name):
    pid = None
    for proc in psutil.process_iter():
        if process_name == proc.name():
            pid = proc.pid
            break
    if(pid == None):
        print("[x] Could not find PID")
    else:
        print(f"[!] Found PID : {pid}")
    return pid

def get_process_handle(pid):
    process_handle = win32api.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    return process_handle

def get_base_address(process_handle):
    modules = win32process.EnumProcessModules(process_handle)
    base_address = modules[0]
    print(f"[!] Found base addess : {hex(base_address)}")
    return base_address

def read_process_memory(proc_handle, base_address, size):
    print(f"[-] Reading memory @ {hex(base_address)}")
    bytes = win32process.ReadProcessMemory(proc_handle, base_address, size)
    return int.from_bytes(bytes, byteorder='little')

def get_pointer_chain_end(proc_handle, base_address, pointer_chain):
    for offset in pointer_chain[0:-1]:
        base_address = read_process_memory(proc_handle, base_address + offset, ctypes.sizeof(ctypes.c_void_p))
    return base_address + pointer_chain[len(pointer_chain) - 1]

def get_money_address(proc_handle):
    pointer_chain = [0x04C42180, 0x5c0, 0x0, 0x8, 0xD0, 0x0, 0x278, 0x108]
    base_address = get_base_address(proc_handle)
    money_pointer_address = get_pointer_chain_end(proc_handle, base_address, pointer_chain)
    return money_pointer_address 

def get_money_value(proc_handle):
    money_pointer_address = get_money_address(proc_handle)
    money_value = read_process_memory(proc_handle, money_pointer_address , ctypes.sizeof(ctypes.c_int))
    return money_value

def set_money_value(proc_handle, value):
    address = get_money_address(proc_handle)
    win32process.WriteProcessMemory(proc_handle, address, value.to_bytes(4,'little'))


if __name__ == '__main__':
    pid = get_pid("Cyberpunk2077.exe")
    proc_handle = get_process_handle(pid)
    money_value = get_money_value(proc_handle)
    print(f"[!] Value found : {money_value}")
    set_money_value(proc_handle, 999999)
    proc_handle.close()

    