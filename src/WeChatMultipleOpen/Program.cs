
using System.Diagnostics;
using System.Runtime.InteropServices;

var t = new Thread(() => {
    while (true)
    {
        foreach (var p in Process.GetProcessesByName("WeChat"))
        {
            CloseMutexHandle(p);
        }
        Thread.Sleep(500);
    }
});
t.IsBackground = true;
t.Start();
t.Join();


[DllImport("ntdll.dll")]
static extern uint NtQuerySystemInformation(int SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength, ref int returnLength);

[DllImport("kernel32.dll")]
static extern IntPtr OpenProcess(PROCESS_ACCESS_FLAGS dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, int dwProcessId);

[DllImport("kernel32.dll", SetLastError = true)]
[return: MarshalAs(UnmanagedType.Bool)]
static extern bool DuplicateHandle(IntPtr hSourceProcessHandle, IntPtr hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle, uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);

[DllImport("kernel32.dll")]
static extern IntPtr GetCurrentProcess();

[DllImport("ntdll.dll")]
static extern int NtQueryObject(IntPtr ObjectHandle, int ObjectInformationClass, IntPtr ObjectInformation, int ObjectInformationLength, ref int returnLength);

[DllImport("kernel32.dll")]
static extern bool CloseHandle(IntPtr hObject);

[DllImport("kernel32.dll")]
static extern bool GetHandleInformation(IntPtr hObject, out uint lpdwFlags);

const uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;
const int DUPLICATE_CLOSE_SOURCE = 0x1;
const int DUPLICATE_SAME_ACCESS = 0x2;

const int CNST_SYSTEM_HANDLE_INFORMATION = 0x10;
const int OBJECT_TYPE_MUTANT = 17;

static List<SYSTEM_HANDLE_INFORMATION> GetHandles(Process process)
{
    List<SYSTEM_HANDLE_INFORMATION> aHandles = new List<SYSTEM_HANDLE_INFORMATION>();
    int handle_info_size = Marshal.SizeOf(new SYSTEM_HANDLE_INFORMATION()) * 20000;
    IntPtr ptrHandleData = IntPtr.Zero;
    try
    {
        ptrHandleData = Marshal.AllocHGlobal(handle_info_size);
        int nLength = 0;

        while (NtQuerySystemInformation(CNST_SYSTEM_HANDLE_INFORMATION, ptrHandleData, handle_info_size, ref nLength) == STATUS_INFO_LENGTH_MISMATCH)
        {
            handle_info_size = nLength;
            Marshal.FreeHGlobal(ptrHandleData);
            ptrHandleData = Marshal.AllocHGlobal(nLength);
        }

        long handle_count = Marshal.ReadIntPtr(ptrHandleData).ToInt64();
        IntPtr ptrHandleItem = ptrHandleData + Marshal.SizeOf(ptrHandleData);

        for (long lIndex = 0; lIndex < handle_count; lIndex++)
        {
            SYSTEM_HANDLE_INFORMATION oSystemHandleInfo = new SYSTEM_HANDLE_INFORMATION();
            oSystemHandleInfo = (SYSTEM_HANDLE_INFORMATION)Marshal.PtrToStructure(ptrHandleItem, oSystemHandleInfo.GetType());
            ptrHandleItem += Marshal.SizeOf(new SYSTEM_HANDLE_INFORMATION());
            if (oSystemHandleInfo.ProcessID != process.Id) { continue; }
            aHandles.Add(oSystemHandleInfo);
        }
    }
    catch (Exception ex)
    {
        throw ex;
    }
    finally
    {
        Marshal.FreeHGlobal(ptrHandleData);
    }
    return aHandles;
}

static bool FindAndCloseWeChatMutexHandle(SYSTEM_HANDLE_INFORMATION systemHandleInformation, Process process)
{
    IntPtr ipHandle = IntPtr.Zero;
    IntPtr openProcessHandle = IntPtr.Zero;
    IntPtr hObjectName = IntPtr.Zero;
    try
    {
        PROCESS_ACCESS_FLAGS flags = PROCESS_ACCESS_FLAGS.DupHandle | PROCESS_ACCESS_FLAGS.VMRead;
        openProcessHandle = OpenProcess(flags, false, process.Id);
        // 通过 DuplicateHandle 访问句柄
        if (!DuplicateHandle(openProcessHandle, new IntPtr(systemHandleInformation.Handle), GetCurrentProcess(), out ipHandle, 0, false, DUPLICATE_SAME_ACCESS))
        {
            return false;
        }

        int nLength = 0;
        hObjectName = Marshal.AllocHGlobal(256 * 1024);

        // 查询句柄名称
        while ((uint)(NtQueryObject(ipHandle, (int)OBJECT_INFORMATION_CLASS.ObjectNameInformation, hObjectName, nLength, ref nLength)) == STATUS_INFO_LENGTH_MISMATCH)
        {
            Marshal.FreeHGlobal(hObjectName);
            if (nLength == 0)
            {
                Console.WriteLine("Length returned at zero!");
                return false;
            }
            hObjectName = Marshal.AllocHGlobal(nLength);
        }
        OBJECT_NAME_INFORMATION objObjectName = new OBJECT_NAME_INFORMATION();
        objObjectName = (OBJECT_NAME_INFORMATION)Marshal.PtrToStructure(hObjectName, objObjectName.GetType());

        if (objObjectName.Name.Buffer != IntPtr.Zero)
        {
            string strObjectName = Marshal.PtrToStringUni(objObjectName.Name.Buffer);
            Console.WriteLine(strObjectName);
            //  \Sessions\1\BaseNamedObjects\_WeChat_App_Instance_Identity_Mutex_Name
            if (strObjectName.EndsWith("_Instance_Identity_Mutex_Name"))
            {
                // 通过 DuplicateHandle DUPLICATE_CLOSE_SOURCE 关闭句柄
                IntPtr mHandle = IntPtr.Zero;
                if (DuplicateHandle(openProcessHandle, new IntPtr(systemHandleInformation.Handle), GetCurrentProcess(), out mHandle, 0, false, DUPLICATE_CLOSE_SOURCE))
                {
                    CloseHandle(mHandle);
                    return true;
                }
            }
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine(ex.Message);
    }
    finally
    {
        Marshal.FreeHGlobal(hObjectName);
        CloseHandle(ipHandle);
        CloseHandle(openProcessHandle);
    }
    return false;
}

static bool CloseMutexHandle(Process process)
{
    bool rt = false;
    List<SYSTEM_HANDLE_INFORMATION> aHandles = GetHandles(process);
    foreach (SYSTEM_HANDLE_INFORMATION handle in aHandles)
    {
        if (FindAndCloseWeChatMutexHandle(handle, process))
        {
            rt = true;
        }
    }
    return rt;
}


[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct SYSTEM_HANDLE_INFORMATION
{
    // Information Class 16
    public ushort ProcessID;
    public ushort CreatorBackTrackIndex;
    public byte ObjectType;
    public byte HandleAttribute;
    public ushort Handle;
    public IntPtr Object_Pointer;
    public IntPtr AccessMask;
}

public enum OBJECT_INFORMATION_CLASS : int
{
    ObjectBasicInformation = 0,
    ObjectNameInformation = 1,
    ObjectTypeInformation = 2,
    ObjectAllTypesInformation = 3,
    ObjectHandleInformation = 4
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct OBJECT_NAME_INFORMATION
{ // Information Class 1
    public UNICODE_STRING Name;
}

[StructLayout(LayoutKind.Sequential)]
public struct UNICODE_STRING
{
    public ushort Length;
    public ushort MaximumLength;
    public IntPtr Buffer;
}

[Flags]
public enum PROCESS_ACCESS_FLAGS : uint
{
    All = 0x001F0FFF,
    Terminate = 0x00000001,
    CreateThread = 0x00000002,
    VMOperation = 0x00000008,
    VMRead = 0x00000010,
    VMWrite = 0x00000020,
    DupHandle = 0x00000040,
    SetInformation = 0x00000200,
    QueryInformation = 0x00000400,
    Synchronize = 0x00100000
}