import ctypes
from ctypes import wintypes

PROCESSOR_ARCHITECTURE_AMD64 = 9
PROCESSOR_ARCHITECTURE_INTEL = 0
PROCESSOR_ARCHITECTURE_ARM = 5
PROCESSOR_ARCHITECTURE_ARM64 = 12


# Структура для получения данных о процессоре
class SYSTEM_INFO(ctypes.Structure):
    _fields_ = [
        ("wProcessorArchitecture", wintypes.WORD),
        ("wReserved", wintypes.WORD),
        ("dwPageSize", wintypes.DWORD),
        ("lpMinimumApplicationAddress", wintypes.LPVOID),
        ("lpMaximumApplicationAddress", wintypes.LPVOID),
        ("dwActiveProcessorMask", ctypes.c_void_p),
        ("dwNumberOfProcessors", wintypes.DWORD),
        ("dwProcessorType", wintypes.DWORD),
        ("dwAllocationGranularity", wintypes.DWORD),
        ("wProcessorLevel", wintypes.WORD),
        ("wProcessorRevision", wintypes.WORD),
    ]


# Структура для получения статуса памяти
class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", wintypes.DWORD),
        ("dwMemoryLoad", wintypes.DWORD),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


# Структура для информации о версии ОС
class OSVERSIONINFOEXW(ctypes.Structure):
    _fields_ = [
        ("dwOSVersionInfoSize", wintypes.DWORD),
        ("dwMajorVersion", wintypes.DWORD),
        ("dwMinorVersion", wintypes.DWORD),
        ("dwBuildNumber", wintypes.DWORD),
        ("dwPlatformId", wintypes.DWORD),
        ("szCSDVersion", wintypes.WCHAR * 128),
        ("wServicePackMajor", wintypes.WORD),
        ("wServicePackMinor", wintypes.WORD),
        ("wSuiteMask", wintypes.WORD),
        ("wProductType", wintypes.BYTE),
        ("wReserved", wintypes.BYTE),
    ]


# Структура для информации о производительности и файле подкачки
class PERFORMANCE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("CommitTotal", ctypes.c_size_t),
        ("CommitLimit", ctypes.c_size_t),
        ("CommitPeak", ctypes.c_size_t),
        ("PhysicalTotal", ctypes.c_size_t),
        ("PhysicalAvailable", ctypes.c_size_t),
        ("SystemCache", ctypes.c_size_t),
        ("KernelTotal", ctypes.c_size_t),
        ("KernelPaged", ctypes.c_size_t),
        ("KernelNonPaged", ctypes.c_size_t),
        ("PageSize", ctypes.c_size_t),
        ("HandleCount", wintypes.DWORD),
        ("ProcessCount", wintypes.DWORD),
        ("ThreadCount", wintypes.DWORD),
    ]


# Конвертация байт в мегабайты (int)
def bytes_to_mb(bytes_val):
    return int(bytes_val / (1024 * 1024))


# Конвертация байт в гигабайты с форматированием
def bytes_to_gb_str(bytes_val):
    gb = bytes_val / (1024 * 1024 * 1024)
    return f"{int(gb)} GB"


# Получение реальной версии ОС (используем ntdll для обхода эмуляции версии)
def get_os_version():
    try:
        os_info = OSVERSIONINFOEXW()
        os_info.dwOSVersionInfoSize = ctypes.sizeof(OSVERSIONINFOEXW)
        ntdll = ctypes.WinDLL('ntdll')
        status = ntdll.RtlGetVersion(ctypes.byref(os_info))
        if status == 0:
            if os_info.dwMajorVersion >= 10:
                return "Windows 10 or Greater"
            return f"Windows {os_info.dwMajorVersion}.{os_info.dwMinorVersion} (Build {os_info.dwBuildNumber})"
    except Exception:
        pass
    return "Unknown OS"


# Получение имени компьютера
def get_computer_name():
    try:
        size = wintypes.DWORD(256)
        buf = ctypes.create_unicode_buffer(size.value)
        if ctypes.windll.kernel32.GetComputerNameW(buf, ctypes.byref(size)):
            return buf.value
    except Exception:
        pass
    return "Unknown"


# Получение имени пользователя (требует advapi32.dll)
def get_user_name():
    try:
        size = wintypes.DWORD(256)
        buf = ctypes.create_unicode_buffer(size.value)
        if ctypes.windll.advapi32.GetUserNameW(buf, ctypes.byref(size)):
            return buf.value
    except Exception:
        pass
    return "Unknown"


# Получение архитектуры процессора (GetNativeSystemInfo для корректной работы в x64)
def get_cpu_info():
    try:
        sys_info = SYSTEM_INFO()
        ctypes.windll.kernel32.GetNativeSystemInfo(ctypes.byref(sys_info))

        arch_map = {
            PROCESSOR_ARCHITECTURE_AMD64: "x64 (AMD64)",
            PROCESSOR_ARCHITECTURE_INTEL: "x86",
            PROCESSOR_ARCHITECTURE_ARM: "ARM",
            PROCESSOR_ARCHITECTURE_ARM64: "ARM64"
        }
        return arch_map.get(sys_info.wProcessorArchitecture, "Unknown"), sys_info.dwNumberOfProcessors
    except Exception:
        return "Unknown", 0


# Получение информации о памяти (GlobalMemoryStatusEx)
def get_memory_info():
    try:
        mem = MEMORYSTATUSEX()
        mem.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(mem)):
            return mem
    except Exception:
        pass
    return None


# Получение информации о системном лимите памяти (RAM + файл подкачки)
def get_pagefile_info():
    try:
        pi = PERFORMANCE_INFORMATION()
        pi.cb = ctypes.sizeof(PERFORMANCE_INFORMATION)
        if ctypes.windll.psapi.GetPerformanceInfo(ctypes.byref(pi), pi.cb):
            total = pi.CommitLimit * pi.PageSize
            used = pi.CommitTotal * pi.PageSize
            return bytes_to_mb(used), bytes_to_mb(total)
    except Exception:
        pass
    return 0, 0


# Получение списка дисков и свободного места
def get_drives_info():
    drives_list = []
    try:
        buf_len = 512
        bitmask = ctypes.create_unicode_buffer(buf_len)
        res = ctypes.windll.kernel32.GetLogicalDriveStringsW(buf_len, bitmask)

        if res > 0:
            raw_data = ctypes.string_at(ctypes.byref(bitmask), res * 2)
            drives = raw_data.decode('utf-16-le').strip('\0').split('\0')

            for d in drives:
                if not d:
                    continue
                free_bytes = ctypes.c_ulonglong(0)
                total_bytes = ctypes.c_ulonglong(0)
                total_free = ctypes.c_ulonglong(0)

                if ctypes.windll.kernel32.GetDiskFreeSpaceExW(d, ctypes.byref(free_bytes), ctypes.byref(total_bytes), ctypes.byref(total_free)):
                    vol_buf = ctypes.create_unicode_buffer(256)
                    fs_buf = ctypes.create_unicode_buffer(256)
                    fs_name = "Unknown"
                    try:
                        ctypes.windll.kernel32.GetVolumeInformationW(d, vol_buf, 256, None, None, None, fs_buf, 256)
                        fs_name = fs_buf.value
                    except:
                        pass
                    drives_list.append({
                        "letter": d,
                        "fs": fs_name,
                        "free": bytes_to_gb_str(free_bytes.value),
                        "total": bytes_to_gb_str(total_bytes.value)
                    })
    except Exception:
        pass
    return drives_list


def main():
    print(f"OS: {get_os_version()}")
    print(f"Computer Name: {get_computer_name()}")
    print(f"User: {get_user_name()}")

    arch, cores = get_cpu_info()
    print(f"Architecture: {arch}")

    mem = get_memory_info()
    if mem:
        used_ram = mem.ullTotalPhys - mem.ullAvailPhys
        print(f"RAM: {bytes_to_mb(used_ram)}MB / {bytes_to_mb(mem.ullTotalPhys)}MB")
        print(f"Virtual Memory: {bytes_to_mb(mem.ullTotalPageFile)}MB")
        print(f"Memory Load: {mem.dwMemoryLoad}%")

    pf_used, pf_total = get_pagefile_info()
    print(f"Pagefile: {pf_used}MB / {pf_total}MB")

    print(f"\nProcessors: {cores}")

    print("Drives:")
    drives = get_drives_info()
    if not drives:
        print("  No drives found or access denied.")
    for d in drives:
        print(f"  - {d['letter']}  ({d['fs']}): {d['free']} free / {d['total']} total")


if __name__ == "__main__":
    main()