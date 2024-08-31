const std = @import("../../std.zig");
const windows = std.os.windows;

const BOOL = windows.BOOL;
const BOOLEAN = windows.BOOLEAN;
const CONDITION_VARIABLE = windows.CONDITION_VARIABLE;
const CONSOLE_SCREEN_BUFFER_INFO = windows.CONSOLE_SCREEN_BUFFER_INFO;
const CONTEXT = windows.CONTEXT;
const COORD = windows.COORD;
const DWORD = windows.DWORD;
const DWORD64 = windows.DWORD64;
const FILE_INFO_BY_HANDLE_CLASS = windows.FILE_INFO_BY_HANDLE_CLASS;
const HANDLE = windows.HANDLE;
const HMODULE = windows.HMODULE;
const HKEY = windows.HKEY;
const HRESULT = windows.HRESULT;
const LARGE_INTEGER = windows.LARGE_INTEGER;
const LPCWSTR = windows.LPCWSTR;
const LPTHREAD_START_ROUTINE = windows.LPTHREAD_START_ROUTINE;
const LPVOID = windows.LPVOID;
const LPWSTR = windows.LPWSTR;
const MODULEINFO = windows.MODULEINFO;
const OVERLAPPED = windows.OVERLAPPED;
const PERFORMANCE_INFORMATION = windows.PERFORMANCE_INFORMATION;
const PROCESS_MEMORY_COUNTERS = windows.PROCESS_MEMORY_COUNTERS;
const PSAPI_WS_WATCH_INFORMATION = windows.PSAPI_WS_WATCH_INFORMATION;
const PSAPI_WS_WATCH_INFORMATION_EX = windows.PSAPI_WS_WATCH_INFORMATION_EX;
const SECURITY_ATTRIBUTES = windows.SECURITY_ATTRIBUTES;
const SIZE_T = windows.SIZE_T;
const SRWLOCK = windows.SRWLOCK;
const UINT = windows.UINT;
const VECTORED_EXCEPTION_HANDLER = windows.VECTORED_EXCEPTION_HANDLER;
const WCHAR = windows.WCHAR;
const WINAPI = windows.WINAPI;
const WORD = windows.WORD;
const Win32Error = windows.Win32Error;
const va_list = windows.va_list;
const HLOCAL = windows.HLOCAL;
const FILETIME = windows.FILETIME;
const STARTUPINFOW = windows.STARTUPINFOW;
const PROCESS_INFORMATION = windows.PROCESS_INFORMATION;
const OVERLAPPED_ENTRY = windows.OVERLAPPED_ENTRY;
const LPHEAP_SUMMARY = windows.LPHEAP_SUMMARY;
const ULONG_PTR = windows.ULONG_PTR;
const FILE_NOTIFY_INFORMATION = windows.FILE_NOTIFY_INFORMATION;
const HANDLER_ROUTINE = windows.HANDLER_ROUTINE;
const ULONG = windows.ULONG;
const PVOID = windows.PVOID;
const LPSTR = windows.LPSTR;
const PENUM_PAGE_FILE_CALLBACKA = windows.PENUM_PAGE_FILE_CALLBACKA;
const PENUM_PAGE_FILE_CALLBACKW = windows.PENUM_PAGE_FILE_CALLBACKW;
const INIT_ONCE = windows.INIT_ONCE;
const CRITICAL_SECTION = windows.CRITICAL_SECTION;
const WIN32_FIND_DATAW = windows.WIN32_FIND_DATAW;
const CHAR = windows.CHAR;
const BY_HANDLE_FILE_INFORMATION = windows.BY_HANDLE_FILE_INFORMATION;
const SYSTEM_INFO = windows.SYSTEM_INFO;
const LPOVERLAPPED_COMPLETION_ROUTINE = windows.LPOVERLAPPED_COMPLETION_ROUTINE;
const UCHAR = windows.UCHAR;
const FARPROC = windows.FARPROC;
const INIT_ONCE_FN = windows.INIT_ONCE_FN;
const PMEMORY_BASIC_INFORMATION = windows.PMEMORY_BASIC_INFORMATION;
const REGSAM = windows.REGSAM;
const LSTATUS = windows.LSTATUS;
const UNWIND_HISTORY_TABLE = windows.UNWIND_HISTORY_TABLE;
const RUNTIME_FUNCTION = windows.RUNTIME_FUNCTION;
const KNONVOLATILE_CONTEXT_POINTERS = windows.KNONVOLATILE_CONTEXT_POINTERS;
const EXCEPTION_ROUTINE = windows.EXCEPTION_ROUTINE;
const MODULEENTRY32 = windows.MODULEENTRY32;
const ULONGLONG = windows.ULONGLONG;

pub extern "kernel32" fn add_vectored_exception_handler(First: c_ulong, Handler: ?VECTORED_EXCEPTION_HANDLER) callconv(WINAPI) ?*anyopaque;
pub extern "kernel32" fn remove_vectored_exception_handler(Handle: HANDLE) callconv(WINAPI) c_ulong;

pub extern "kernel32" fn cancel_io(hFile: HANDLE) callconv(WINAPI) BOOL;
pub extern "kernel32" fn cancel_io_ex(hFile: HANDLE, lpOverlapped: ?*OVERLAPPED) callconv(WINAPI) BOOL;

pub extern "kernel32" fn close_handle(hObject: HANDLE) callconv(WINAPI) BOOL;

pub extern "kernel32" fn create_directory_w(lpPathName: [*:0]const u16, lpSecurityAttributes: ?*SECURITY_ATTRIBUTES) callconv(WINAPI) BOOL;
pub extern "kernel32" fn set_end_of_file(hFile: HANDLE) callconv(WINAPI) BOOL;

pub extern "kernel32" fn create_event_ex_w(
    lpEventAttributes: ?*SECURITY_ATTRIBUTES,
    lpName: ?LPCWSTR,
    dwFlags: DWORD,
    dwDesiredAccess: DWORD,
) callconv(WINAPI) ?HANDLE;

pub extern "kernel32" fn create_file_w(
    lpFileName: [*:0]const u16,
    dwDesiredAccess: DWORD,
    dwShareMode: DWORD,
    lpSecurityAttributes: ?*SECURITY_ATTRIBUTES,
    dwCreationDisposition: DWORD,
    dwFlagsAndAttributes: DWORD,
    hTemplateFile: ?HANDLE,
) callconv(WINAPI) HANDLE;

pub extern "kernel32" fn create_pipe(
    hReadPipe: *HANDLE,
    hWritePipe: *HANDLE,
    lpPipeAttributes: *const SECURITY_ATTRIBUTES,
    nSize: DWORD,
) callconv(WINAPI) BOOL;

pub extern "kernel32" fn create_named_pipe_w(
    lpName: LPCWSTR,
    dwOpenMode: DWORD,
    dwPipeMode: DWORD,
    nMaxInstances: DWORD,
    nOutBufferSize: DWORD,
    nInBufferSize: DWORD,
    nDefaultTimeOut: DWORD,
    lpSecurityAttributes: ?*const SECURITY_ATTRIBUTES,
) callconv(WINAPI) HANDLE;

pub extern "kernel32" fn create_process_w(
    lpApplicationName: ?LPCWSTR,
    lpCommandLine: ?LPWSTR,
    lpProcessAttributes: ?*SECURITY_ATTRIBUTES,
    lpThreadAttributes: ?*SECURITY_ATTRIBUTES,
    bInheritHandles: BOOL,
    dwCreationFlags: DWORD,
    lpEnvironment: ?*anyopaque,
    lpCurrentDirectory: ?LPCWSTR,
    lpStartupInfo: *STARTUPINFOW,
    lpProcessInformation: *PROCESS_INFORMATION,
) callconv(WINAPI) BOOL;

pub extern "kernel32" fn create_symbolic_link_w(lpSymlinkFileName: [*:0]const u16, lpTargetFileName: [*:0]const u16, dwFlags: DWORD) callconv(WINAPI) BOOLEAN;

pub extern "kernel32" fn create_io_completion_port(FileHandle: HANDLE, ExistingCompletionPort: ?HANDLE, CompletionKey: ULONG_PTR, NumberOfConcurrentThreads: DWORD) callconv(WINAPI) ?HANDLE;

pub extern "kernel32" fn create_thread(lpThreadAttributes: ?*SECURITY_ATTRIBUTES, dwStackSize: SIZE_T, lpStartAddress: LPTHREAD_START_ROUTINE, lpParameter: ?LPVOID, dwCreationFlags: DWORD, lpThreadId: ?*DWORD) callconv(WINAPI) ?HANDLE;

pub extern "kernel32" fn create_toolhelp32_snapshot(dwFlags: DWORD, th32ProcessID: DWORD) callconv(WINAPI) HANDLE;

pub extern "kernel32" fn device_io_control(
    h: HANDLE,
    dwIoControlCode: DWORD,
    lpInBuffer: ?*const anyopaque,
    nInBufferSize: DWORD,
    lpOutBuffer: ?LPVOID,
    nOutBufferSize: DWORD,
    lpBytesReturned: ?*DWORD,
    lpOverlapped: ?*OVERLAPPED,
) callconv(WINAPI) BOOL;

pub extern "kernel32" fn delete_file_w(lpFileName: [*:0]const u16) callconv(WINAPI) BOOL;

pub extern "kernel32" fn duplicate_handle(hSourceProcessHandle: HANDLE, hSourceHandle: HANDLE, hTargetProcessHandle: HANDLE, lpTargetHandle: *HANDLE, dwDesiredAccess: DWORD, bInheritHandle: BOOL, dwOptions: DWORD) callconv(WINAPI) BOOL;

pub extern "kernel32" fn exit_process(exit_code: UINT) callconv(WINAPI) noreturn;

pub extern "kernel32" fn find_first_file_w(lpFileName: [*:0]const u16, lpFindFileData: *WIN32_FIND_DATAW) callconv(WINAPI) HANDLE;
pub extern "kernel32" fn find_close(hFindFile: HANDLE) callconv(WINAPI) BOOL;
pub extern "kernel32" fn find_next_file_w(hFindFile: HANDLE, lpFindFileData: *WIN32_FIND_DATAW) callconv(WINAPI) BOOL;

pub extern "kernel32" fn format_message_w(dwFlags: DWORD, lpSource: ?LPVOID, dwMessageId: Win32Error, dwLanguageId: DWORD, lpBuffer: [*]u16, nSize: DWORD, Arguments: ?*va_list) callconv(WINAPI) DWORD;

pub extern "kernel32" fn free_environment_strings_w(penv: [*:0]u16) callconv(WINAPI) BOOL;

pub extern "kernel32" fn get_command_line_a() callconv(WINAPI) LPSTR;
pub extern "kernel32" fn get_command_line_w() callconv(WINAPI) LPWSTR;

pub extern "kernel32" fn get_console_mode(in_hConsoleHandle: HANDLE, out_lpMode: *DWORD) callconv(WINAPI) BOOL;
pub extern "kernel32" fn set_console_mode(in_hConsoleHandle: HANDLE, in_dwMode: DWORD) callconv(WINAPI) BOOL;

pub extern "kernel32" fn get_console_output_cp() callconv(WINAPI) UINT;

pub extern "kernel32" fn get_console_screen_buffer_info(hConsoleOutput: HANDLE, lpConsoleScreenBufferInfo: *CONSOLE_SCREEN_BUFFER_INFO) callconv(WINAPI) BOOL;
pub extern "kernel32" fn fill_console_output_character_a(hConsoleOutput: HANDLE, cCharacter: CHAR, nLength: DWORD, dwWriteCoord: COORD, lpNumberOfCharsWritten: *DWORD) callconv(WINAPI) BOOL;
pub extern "kernel32" fn fill_console_output_character_w(hConsoleOutput: HANDLE, cCharacter: WCHAR, nLength: DWORD, dwWriteCoord: COORD, lpNumberOfCharsWritten: *DWORD) callconv(WINAPI) BOOL;
pub extern "kernel32" fn fill_console_output_attribute(hConsoleOutput: HANDLE, wAttribute: WORD, nLength: DWORD, dwWriteCoord: COORD, lpNumberOfAttrsWritten: *DWORD) callconv(WINAPI) BOOL;
pub extern "kernel32" fn set_console_cursor_position(hConsoleOutput: HANDLE, dwCursorPosition: COORD) callconv(WINAPI) BOOL;

pub extern "kernel32" fn write_console_w(hConsoleOutput: HANDLE, lpBuffer: [*]const u16, nNumberOfCharsToWrite: DWORD, lpNumberOfCharsWritten: ?*DWORD, lpReserved: ?LPVOID) callconv(WINAPI) BOOL;
pub extern "kernel32" fn read_console_output_character_w(
    hConsoleOutput: windows.HANDLE,
    lpCharacter: [*]u16,
    nLength: windows.DWORD,
    dwReadCoord: windows.COORD,
    lpNumberOfCharsRead: *windows.DWORD,
) callconv(windows.WINAPI) windows.BOOL;

pub extern "kernel32" fn get_current_directory_w(nBufferLength: DWORD, lpBuffer: ?[*]WCHAR) callconv(WINAPI) DWORD;

pub extern "kernel32" fn get_current_thread() callconv(WINAPI) HANDLE;
pub extern "kernel32" fn get_current_thread_id() callconv(WINAPI) DWORD;

pub extern "kernel32" fn get_current_process_id() callconv(WINAPI) DWORD;

pub extern "kernel32" fn get_current_process() callconv(WINAPI) HANDLE;

pub extern "kernel32" fn get_environment_strings_w() callconv(WINAPI) ?[*:0]u16;

pub extern "kernel32" fn get_environment_variable_w(lpName: LPWSTR, lpBuffer: [*]u16, nSize: DWORD) callconv(WINAPI) DWORD;

pub extern "kernel32" fn set_environment_variable_w(lpName: LPCWSTR, lpValue: ?LPCWSTR) callconv(WINAPI) BOOL;

pub extern "kernel32" fn get_exit_code_process(hProcess: HANDLE, lpExitCode: *DWORD) callconv(WINAPI) BOOL;

pub extern "kernel32" fn get_file_size_ex(hFile: HANDLE, lpFileSize: *LARGE_INTEGER) callconv(WINAPI) BOOL;

pub extern "kernel32" fn get_file_attributes_w(lpFileName: [*:0]const WCHAR) callconv(WINAPI) DWORD;

pub extern "kernel32" fn get_module_file_name_w(hModule: ?HMODULE, lpFilename: [*]u16, nSize: DWORD) callconv(WINAPI) DWORD;

pub extern "kernel32" fn get_module_handle_w(lpModuleName: ?[*:0]const WCHAR) callconv(WINAPI) ?HMODULE;

pub extern "kernel32" fn get_last_error() callconv(WINAPI) Win32Error;
pub extern "kernel32" fn set_last_error(dwErrCode: Win32Error) callconv(WINAPI) void;

pub extern "kernel32" fn get_file_information_by_handle_ex(
    in_hFile: HANDLE,
    in_FileInformationClass: FILE_INFO_BY_HANDLE_CLASS,
    out_lpFileInformation: *anyopaque,
    in_dwBufferSize: DWORD,
) callconv(WINAPI) BOOL;

pub extern "kernel32" fn get_final_path_name_by_handle_w(
    hFile: HANDLE,
    lpszFilePath: [*]u16,
    cchFilePath: DWORD,
    dwFlags: DWORD,
) callconv(WINAPI) DWORD;

pub extern "kernel32" fn get_full_path_name_w(
    lpFileName: [*:0]const u16,
    nBufferLength: u32,
    lpBuffer: [*]u16,
    lpFilePart: ?*?[*:0]u16,
) callconv(@import("std").os.windows.WINAPI) u32;

pub extern "kernel32" fn get_overlapped_result(hFile: HANDLE, lpOverlapped: *OVERLAPPED, lpNumberOfBytesTransferred: *DWORD, bWait: BOOL) callconv(WINAPI) BOOL;

pub extern "kernel32" fn get_process_heap() callconv(WINAPI) ?HANDLE;

pub extern "kernel32" fn get_process_times(in_hProcess: HANDLE, out_lpCreationTime: *FILETIME, out_lpExitTime: *FILETIME, out_lpKernelTime: *FILETIME, out_lpUserTime: *FILETIME) callconv(WINAPI) BOOL;

pub extern "kernel32" fn get_queued_completion_status(CompletionPort: HANDLE, lpNumberOfBytesTransferred: *DWORD, lpCompletionKey: *ULONG_PTR, lpOverlapped: *?*OVERLAPPED, dwMilliseconds: DWORD) callconv(WINAPI) BOOL;
pub extern "kernel32" fn get_queued_completion_status_ex(
    CompletionPort: HANDLE,
    lpCompletionPortEntries: [*]OVERLAPPED_ENTRY,
    ulCount: ULONG,
    ulNumEntriesRemoved: *ULONG,
    dwMilliseconds: DWORD,
    fAlertable: BOOL,
) callconv(WINAPI) BOOL;

pub extern "kernel32" fn get_system_info(lpSystemInfo: *SYSTEM_INFO) callconv(WINAPI) void;
pub extern "kernel32" fn get_system_time_as_file_time(*FILETIME) callconv(WINAPI) void;
pub extern "kernel32" fn is_processor_feature_present(ProcessorFeature: DWORD) BOOL;

pub extern "kernel32" fn get_system_directory_w(lpBuffer: LPWSTR, uSize: UINT) callconv(WINAPI) UINT;

pub extern "kernel32" fn heap_create(flOptions: DWORD, dwInitialSize: SIZE_T, dwMaximumSize: SIZE_T) callconv(WINAPI) ?HANDLE;
pub extern "kernel32" fn heap_destroy(hHeap: HANDLE) callconv(WINAPI) BOOL;
pub extern "kernel32" fn heap_re_alloc(hHeap: HANDLE, dwFlags: DWORD, lpMem: *anyopaque, dwBytes: SIZE_T) callconv(WINAPI) ?*anyopaque;
pub extern "kernel32" fn heap_size(hHeap: HANDLE, dwFlags: DWORD, lpMem: *const anyopaque) callconv(WINAPI) SIZE_T;
pub extern "kernel32" fn heap_compact(hHeap: HANDLE, dwFlags: DWORD) callconv(WINAPI) SIZE_T;
pub extern "kernel32" fn heap_summary(hHeap: HANDLE, dwFlags: DWORD, lpSummary: LPHEAP_SUMMARY) callconv(WINAPI) BOOL;

pub extern "kernel32" fn get_std_handle(in_nStdHandle: DWORD) callconv(WINAPI) ?HANDLE;

pub extern "kernel32" fn heap_alloc(hHeap: HANDLE, dwFlags: DWORD, dwBytes: SIZE_T) callconv(WINAPI) ?*anyopaque;

pub extern "kernel32" fn heap_free(hHeap: HANDLE, dwFlags: DWORD, lpMem: *anyopaque) callconv(WINAPI) BOOL;

pub extern "kernel32" fn heap_validate(hHeap: HANDLE, dwFlags: DWORD, lpMem: ?*const anyopaque) callconv(WINAPI) BOOL;

pub extern "kernel32" fn virtual_alloc(lpAddress: ?LPVOID, dwSize: SIZE_T, flAllocationType: DWORD, flProtect: DWORD) callconv(WINAPI) ?LPVOID;
pub extern "kernel32" fn virtual_free(lpAddress: ?LPVOID, dwSize: SIZE_T, dwFreeType: DWORD) callconv(WINAPI) BOOL;
pub extern "kernel32" fn virtual_query(lpAddress: ?LPVOID, lpBuffer: PMEMORY_BASIC_INFORMATION, dwLength: SIZE_T) callconv(WINAPI) SIZE_T;

pub extern "kernel32" fn local_free(hMem: HLOCAL) callconv(WINAPI) ?HLOCAL;

pub extern "kernel32" fn module32_first(hSnapshot: HANDLE, lpme: *MODULEENTRY32) callconv(WINAPI) BOOL;

pub extern "kernel32" fn module32_next(hSnapshot: HANDLE, lpme: *MODULEENTRY32) callconv(WINAPI) BOOL;

pub extern "kernel32" fn move_file_ex_w(
    lpExistingFileName: [*:0]const u16,
    lpNewFileName: [*:0]const u16,
    dwFlags: DWORD,
) callconv(WINAPI) BOOL;

pub extern "kernel32" fn post_queued_completion_status(CompletionPort: HANDLE, dwNumberOfBytesTransferred: DWORD, dwCompletionKey: ULONG_PTR, lpOverlapped: ?*OVERLAPPED) callconv(WINAPI) BOOL;

pub extern "kernel32" fn read_directory_changes_w(
    hDirectory: HANDLE,
    lpBuffer: [*]align(@alignOf(FILE_NOTIFY_INFORMATION)) u8,
    nBufferLength: DWORD,
    bWatchSubtree: BOOL,
    dwNotifyFilter: DWORD,
    lpBytesReturned: ?*DWORD,
    lpOverlapped: ?*OVERLAPPED,
    lpCompletionRoutine: LPOVERLAPPED_COMPLETION_ROUTINE,
) callconv(WINAPI) BOOL;

pub extern "kernel32" fn read_file(
    in_hFile: HANDLE,
    out_lpBuffer: [*]u8,
    in_nNumberOfBytesToRead: DWORD,
    out_lpNumberOfBytesRead: ?*DWORD,
    in_out_lpOverlapped: ?*OVERLAPPED,
) callconv(WINAPI) BOOL;

pub extern "kernel32" fn remove_directory_w(lpPathName: [*:0]const u16) callconv(WINAPI) BOOL;

pub extern "kernel32" fn rtl_capture_context(ContextRecord: *CONTEXT) callconv(WINAPI) void;

pub extern "kernel32" fn rtl_lookup_function_entry(
    ControlPc: DWORD64,
    ImageBase: *DWORD64,
    HistoryTable: *UNWIND_HISTORY_TABLE,
) callconv(WINAPI) ?*RUNTIME_FUNCTION;

pub extern "kernel32" fn rtl_virtual_unwind(
    HandlerType: DWORD,
    ImageBase: DWORD64,
    ControlPc: DWORD64,
    FunctionEntry: *RUNTIME_FUNCTION,
    ContextRecord: *CONTEXT,
    HandlerData: *?PVOID,
    EstablisherFrame: *DWORD64,
    ContextPointers: ?*KNONVOLATILE_CONTEXT_POINTERS,
) callconv(WINAPI) *EXCEPTION_ROUTINE;

pub extern "kernel32" fn set_console_text_attribute(hConsoleOutput: HANDLE, wAttributes: WORD) callconv(WINAPI) BOOL;

pub extern "kernel32" fn set_console_ctrl_handler(
    HandlerRoutine: ?HANDLER_ROUTINE,
    Add: BOOL,
) callconv(WINAPI) BOOL;

pub extern "kernel32" fn set_console_output_cp(wCodePageID: UINT) callconv(WINAPI) BOOL;

pub extern "kernel32" fn set_file_completion_notification_modes(
    FileHandle: HANDLE,
    Flags: UCHAR,
) callconv(WINAPI) BOOL;

pub extern "kernel32" fn set_file_pointer_ex(
    in_fFile: HANDLE,
    in_liDistanceToMove: LARGE_INTEGER,
    out_opt_ldNewFilePointer: ?*LARGE_INTEGER,
    in_dwMoveMethod: DWORD,
) callconv(WINAPI) BOOL;

pub extern "kernel32" fn set_file_time(
    hFile: HANDLE,
    lpCreationTime: ?*const FILETIME,
    lpLastAccessTime: ?*const FILETIME,
    lpLastWriteTime: ?*const FILETIME,
) callconv(WINAPI) BOOL;

pub extern "kernel32" fn set_handle_information(hObject: HANDLE, dwMask: DWORD, dwFlags: DWORD) callconv(WINAPI) BOOL;

pub extern "kernel32" fn sleep(dwMilliseconds: DWORD) callconv(WINAPI) void;

pub extern "kernel32" fn switch_to_thread() callconv(WINAPI) BOOL;

pub extern "kernel32" fn terminate_process(hProcess: HANDLE, uExitCode: UINT) callconv(WINAPI) BOOL;

pub extern "kernel32" fn tls_alloc() callconv(WINAPI) DWORD;

pub extern "kernel32" fn tls_free(dwTlsIndex: DWORD) callconv(WINAPI) BOOL;

pub extern "kernel32" fn wait_for_single_object(hHandle: HANDLE, dwMilliseconds: DWORD) callconv(WINAPI) DWORD;

pub extern "kernel32" fn wait_for_single_object_ex(hHandle: HANDLE, dwMilliseconds: DWORD, bAlertable: BOOL) callconv(WINAPI) DWORD;

pub extern "kernel32" fn wait_for_multiple_objects(nCount: DWORD, lpHandle: [*]const HANDLE, bWaitAll: BOOL, dwMilliseconds: DWORD) callconv(WINAPI) DWORD;

pub extern "kernel32" fn wait_for_multiple_objects_ex(
    nCount: DWORD,
    lpHandle: [*]const HANDLE,
    bWaitAll: BOOL,
    dwMilliseconds: DWORD,
    bAlertable: BOOL,
) callconv(WINAPI) DWORD;

pub extern "kernel32" fn write_file(
    in_hFile: HANDLE,
    in_lpBuffer: [*]const u8,
    in_nNumberOfBytesToWrite: DWORD,
    out_lpNumberOfBytesWritten: ?*DWORD,
    in_out_lpOverlapped: ?*OVERLAPPED,
) callconv(WINAPI) BOOL;

pub extern "kernel32" fn write_file_ex(
    hFile: HANDLE,
    lpBuffer: [*]const u8,
    nNumberOfBytesToWrite: DWORD,
    lpOverlapped: *OVERLAPPED,
    lpCompletionRoutine: LPOVERLAPPED_COMPLETION_ROUTINE,
) callconv(WINAPI) BOOL;

pub extern "kernel32" fn load_library_w(lpLibFileName: [*:0]const u16) callconv(WINAPI) ?HMODULE;
pub extern "kernel32" fn load_library_ex_w(lpLibFileName: [*:0]const u16, hFile: ?HANDLE, dwFlags: DWORD) callconv(WINAPI) ?HMODULE;

pub extern "kernel32" fn get_proc_address(hModule: HMODULE, lpProcName: [*:0]const u8) callconv(WINAPI) ?FARPROC;

pub extern "kernel32" fn free_library(hModule: HMODULE) callconv(WINAPI) BOOL;

pub extern "kernel32" fn initialize_critical_section(lpCriticalSection: *CRITICAL_SECTION) callconv(WINAPI) void;
pub extern "kernel32" fn enter_critical_section(lpCriticalSection: *CRITICAL_SECTION) callconv(WINAPI) void;
pub extern "kernel32" fn leave_critical_section(lpCriticalSection: *CRITICAL_SECTION) callconv(WINAPI) void;
pub extern "kernel32" fn delete_critical_section(lpCriticalSection: *CRITICAL_SECTION) callconv(WINAPI) void;

pub extern "kernel32" fn init_once_execute_once(InitOnce: *INIT_ONCE, InitFn: INIT_ONCE_FN, Parameter: ?*anyopaque, Context: ?*anyopaque) callconv(WINAPI) BOOL;

pub extern "kernel32" fn k32_empty_working_set(hProcess: HANDLE) callconv(WINAPI) BOOL;
pub extern "kernel32" fn k32_enum_device_drivers(lpImageBase: [*]LPVOID, cb: DWORD, lpcbNeeded: *DWORD) callconv(WINAPI) BOOL;
pub extern "kernel32" fn k32_enum_page_files_a(pCallBackRoutine: PENUM_PAGE_FILE_CALLBACKA, pContext: LPVOID) callconv(WINAPI) BOOL;
pub extern "kernel32" fn k32_enum_page_files_w(pCallBackRoutine: PENUM_PAGE_FILE_CALLBACKW, pContext: LPVOID) callconv(WINAPI) BOOL;
pub extern "kernel32" fn k32_enum_process_modules(hProcess: HANDLE, lphModule: [*]HMODULE, cb: DWORD, lpcbNeeded: *DWORD) callconv(WINAPI) BOOL;
pub extern "kernel32" fn k32_enum_process_modules_ex(hProcess: HANDLE, lphModule: [*]HMODULE, cb: DWORD, lpcbNeeded: *DWORD, dwFilterFlag: DWORD) callconv(WINAPI) BOOL;
pub extern "kernel32" fn k32_enum_processes(lpidProcess: [*]DWORD, cb: DWORD, cbNeeded: *DWORD) callconv(WINAPI) BOOL;
pub extern "kernel32" fn k32_get_device_driver_base_name_a(ImageBase: LPVOID, lpBaseName: LPSTR, nSize: DWORD) callconv(WINAPI) DWORD;
pub extern "kernel32" fn k32_get_device_driver_base_name_w(ImageBase: LPVOID, lpBaseName: LPWSTR, nSize: DWORD) callconv(WINAPI) DWORD;
pub extern "kernel32" fn k32_get_device_driver_file_name_a(ImageBase: LPVOID, lpFilename: LPSTR, nSize: DWORD) callconv(WINAPI) DWORD;
pub extern "kernel32" fn k32_get_device_driver_file_name_w(ImageBase: LPVOID, lpFilename: LPWSTR, nSize: DWORD) callconv(WINAPI) DWORD;
pub extern "kernel32" fn k32_get_mapped_file_name_a(hProcess: HANDLE, lpv: ?LPVOID, lpFilename: LPSTR, nSize: DWORD) callconv(WINAPI) DWORD;
pub extern "kernel32" fn k32_get_mapped_file_name_w(hProcess: HANDLE, lpv: ?LPVOID, lpFilename: LPWSTR, nSize: DWORD) callconv(WINAPI) DWORD;
pub extern "kernel32" fn k32_get_module_base_name_a(hProcess: HANDLE, hModule: ?HMODULE, lpBaseName: LPSTR, nSize: DWORD) callconv(WINAPI) DWORD;
pub extern "kernel32" fn k32_get_module_base_name_w(hProcess: HANDLE, hModule: ?HMODULE, lpBaseName: LPWSTR, nSize: DWORD) callconv(WINAPI) DWORD;
pub extern "kernel32" fn k32_get_module_file_name_ex_a(hProcess: HANDLE, hModule: ?HMODULE, lpFilename: LPSTR, nSize: DWORD) callconv(WINAPI) DWORD;
pub extern "kernel32" fn k32_get_module_file_name_ex_w(hProcess: HANDLE, hModule: ?HMODULE, lpFilename: LPWSTR, nSize: DWORD) callconv(WINAPI) DWORD;
pub extern "kernel32" fn k32_get_module_information(hProcess: HANDLE, hModule: HMODULE, lpmodinfo: *MODULEINFO, cb: DWORD) callconv(WINAPI) BOOL;
pub extern "kernel32" fn k32_get_performance_info(pPerformanceInformation: *PERFORMANCE_INFORMATION, cb: DWORD) callconv(WINAPI) BOOL;
pub extern "kernel32" fn k32_get_process_image_file_name_a(hProcess: HANDLE, lpImageFileName: LPSTR, nSize: DWORD) callconv(WINAPI) DWORD;
pub extern "kernel32" fn k32_get_process_image_file_name_w(hProcess: HANDLE, lpImageFileName: LPWSTR, nSize: DWORD) callconv(WINAPI) DWORD;
pub extern "kernel32" fn k32_get_process_memory_info(Process: HANDLE, ppsmemCounters: *PROCESS_MEMORY_COUNTERS, cb: DWORD) callconv(WINAPI) BOOL;
pub extern "kernel32" fn k32_get_ws_changes(hProcess: HANDLE, lpWatchInfo: *PSAPI_WS_WATCH_INFORMATION, cb: DWORD) callconv(WINAPI) BOOL;
pub extern "kernel32" fn k32_get_ws_changes_ex(hProcess: HANDLE, lpWatchInfoEx: *PSAPI_WS_WATCH_INFORMATION_EX, cb: DWORD) callconv(WINAPI) BOOL;
pub extern "kernel32" fn k32_initialize_process_for_ws_watch(hProcess: HANDLE) callconv(WINAPI) BOOL;
pub extern "kernel32" fn k32_query_working_set(hProcess: HANDLE, pv: PVOID, cb: DWORD) callconv(WINAPI) BOOL;
pub extern "kernel32" fn k32_query_working_set_ex(hProcess: HANDLE, pv: PVOID, cb: DWORD) callconv(WINAPI) BOOL;

pub extern "kernel32" fn flush_file_buffers(hFile: HANDLE) callconv(WINAPI) BOOL;

pub extern "kernel32" fn wake_all_condition_variable(c: *CONDITION_VARIABLE) callconv(WINAPI) void;
pub extern "kernel32" fn wake_condition_variable(c: *CONDITION_VARIABLE) callconv(WINAPI) void;
pub extern "kernel32" fn sleep_condition_variable_srw(
    c: *CONDITION_VARIABLE,
    s: *SRWLOCK,
    t: DWORD,
    f: ULONG,
) callconv(WINAPI) BOOL;

pub extern "kernel32" fn try_acquire_srwlock_exclusive(s: *SRWLOCK) callconv(WINAPI) BOOLEAN;
pub extern "kernel32" fn acquire_srwlock_exclusive(s: *SRWLOCK) callconv(WINAPI) void;
pub extern "kernel32" fn release_srwlock_exclusive(s: *SRWLOCK) callconv(WINAPI) void;

pub extern "kernel32" fn reg_open_key_ex_w(
    hkey: HKEY,
    lpSubKey: LPCWSTR,
    ulOptions: DWORD,
    samDesired: REGSAM,
    phkResult: *HKEY,
) callconv(WINAPI) LSTATUS;

pub extern "kernel32" fn get_physically_installed_system_memory(TotalMemoryInKilobytes: *ULONGLONG) BOOL;
