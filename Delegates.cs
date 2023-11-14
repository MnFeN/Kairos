using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Text.RegularExpressions;
using Triggernometry.Variables;

var TriggernometryHelpers = new Triggernometry.Interpreter.Helpers(); // 粘贴到触发器后注释掉此行

#region 进程管理
Process GetProcess()
{
    var store = TriggernometryHelpers.Storage;
    int procId = (int)TriggernometryHelpers.EvaluateNumericExpression("0${_ffxivprocid}");
    if (!store.ContainsKey("procId") || store["procId"].ToString() != procId.ToString())
    {
        if (store.ContainsKey("procId"))
        {
            Process oldProc = (Process)TriggernometryHelpers.Storage["proc"];
            oldProc.Dispose();
        }
        Process proc = Process.GetProcessById(procId);
        TriggernometryHelpers.Storage["proc"] = proc;
        TriggernometryHelpers.Storage["procId"] = procId;
        return proc;
    }
    else
    {
        return (Process)TriggernometryHelpers.Storage["proc"];
    }
}

TriggernometryHelpers.Delegates["GetProcess"] = new Func<Process>(GetProcess);
GetProcess();

#endregion

#region 内存读写

[DllImport("kernel32.dll", SetLastError = true)]
[SuppressUnmanagedCodeSecurity]
static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, uint dwSize, out int lpBytesRead);

[DllImport("kernel32.dll", SetLastError = true)]
[SuppressUnmanagedCodeSecurity]
static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint dwSize, out int lpBytesWritten);

byte[] ReadBytes(Process process, IntPtr address, uint size)
{
    byte[] lpBuffer = new byte[size];
    ReadProcessMemory(process.Handle, address, lpBuffer, size, out _);
    return lpBuffer;
}

void WriteBytes(Process process, IntPtr address, uint size, byte[] newValue)
{
    WriteProcessMemory(process.Handle, address, newValue, size, out _);
}

T Read<T>(Process process, IntPtr address)
{
    byte[] valueBytes = new byte[Marshal.SizeOf<T>()];
    ReadProcessMemory(process.Handle, address, valueBytes, (uint)valueBytes.Length, out _);
    GCHandle handle = GCHandle.Alloc(valueBytes, GCHandleType.Pinned);
    T value = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
    handle.Free();
    return value;
}

void Write<T>(Process process, IntPtr address, T newValue)
{
    byte[] valueBytes = new byte[Marshal.SizeOf<T>()];
    GCHandle handle = GCHandle.Alloc(valueBytes, GCHandleType.Pinned);
    Marshal.StructureToPtr(newValue, handle.AddrOfPinnedObject(), true);
    handle.Free();
    WriteProcessMemory(process.Handle, address, valueBytes, (uint)valueBytes.Length, out _);
}

TriggernometryHelpers.Delegates["ReadBytes"] = new Func<Process, IntPtr, uint, byte[]>(ReadBytes);
TriggernometryHelpers.Delegates["WriteBytes"] = new Action<Process, IntPtr, uint, byte[]>(WriteBytes);

TriggernometryHelpers.Delegates["ReadFloat"] = new Func<Process, IntPtr, float>(Read<float>);
TriggernometryHelpers.Delegates["WriteFloat"] = new Action<Process, IntPtr, float>(Write);

TriggernometryHelpers.Delegates["ReadDouble"] = new Func<Process, IntPtr, double>(Read<double>);
TriggernometryHelpers.Delegates["WriteDouble"] = new Action<Process, IntPtr, double>(Write);

TriggernometryHelpers.Delegates["ReadInt"] = new Func<Process, IntPtr, int>(Read<int>);
TriggernometryHelpers.Delegates["WriteInt"] = new Action<Process, IntPtr, int>(Write);

TriggernometryHelpers.Delegates["ReadLong"] = new Func<Process, IntPtr, long>(Read<long>);
TriggernometryHelpers.Delegates["WriteLong"] = new Action<Process, IntPtr, long>(Write);

#endregion

#region 内存搜索

byte?[] ParsePatternString(string patternStr)
{
    patternStr = patternStr.Trim();
    string[] patternStrs;

    if (!patternStr.Contains(" ")) // "010203????ff"
    {
        if (patternStr.Length % 2 == 1)
        {
            throw new Exception($"内存特征 pattern 字符串 {patternStr} 长度不应为奇数。");
        }
        patternStrs = Enumerable.Range(0, patternStr.Length / 2).Select(idx => patternStr.Substring(idx * 2, 2)).ToArray();
    }
    else // "01 02 03 ?? ?? ff" or "01 02 03 ? ? ff"
    {
        patternStr = Regex.Replace(patternStr, @"(?<= |^)\?(?= |$)", "??");
        patternStrs = patternStr.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
    }

    return patternStrs.Select(str => {
        if (str == "??")
        {
            return null;
        }
        if (byte.TryParse(str, NumberStyles.HexNumber, null, out byte result))
        {
            return (byte?)result;
        }
        else
        {
            throw new FormatException($"内存特征 pattern 字符串中包含无法解析的 byte：{str}");
        }
    }).ToArray();
}

byte[] ReadModuleMemory(Process proc)
{
    int moduleSize = proc.MainModule.ModuleMemorySize;
    byte[] moduleData = new byte[moduleSize];
    ReadProcessMemory(proc.Handle, proc.MainModule.BaseAddress, moduleData, (uint)moduleSize, out _);
    return moduleData;
}

int MemScanner(byte[] moduleData, string patternStr)
{
    byte?[] pattern = ParsePatternString(patternStr);

    // KMP 算法搜索
    int[] next = new int[pattern.Length];
    next[0] = -1;

    int i = 0, j = -1;
    while (i < pattern.Length - 1)
    {
        if (j == -1 || pattern[i] == null || pattern[i] == pattern[j])
            next[++i] = ++j;
        else
            j = next[j];
    }

    i = 0; j = 0;
    while (i < moduleData.Length && j < pattern.Length)
    {
        if (j == -1 || pattern[j] == null || moduleData[i] == pattern[j])
        {
            i++; j++;
        }
        else
            j = next[j];
    }
    if (j == pattern.Length)
    {
        int address = i - j;
        TriggernometryHelpers.Log(Triggernometry.RealPlugin.DebugLevelEnum.Custom, $"成功在 {address} 处找到内存特征：{patternStr}");
        return address;
    }
    else
    {
        TriggernometryHelpers.Log(Triggernometry.RealPlugin.DebugLevelEnum.Error, $"未找到内存特征：{patternStr}");
        return -1;
    }
}
TriggernometryHelpers.Delegates["ReadModuleMemory"] = new Func<Process, byte[]>(ReadModuleMemory);
TriggernometryHelpers.Delegates["MemScanner"] = new Func<byte[], string, int>(MemScanner);
#endregion

#region 相机参数
IntPtr GetCameraAddress(Process proc)   // Github svr2kos2/FFXIV_ACT_ViewUnlocker
{
    byte[] moduleData = ReadModuleMemory(proc);
    string pattern =
        "48 83 c4 28 " +                                // add rsp, 28
        "e9 ?? ?? ?? ?? " +                             // jmp xxxxxxxx
        "cc cc cc cc cc cc cc cc cc cc cc cc cc " +     // int 3 * 13
        "48 8d 0d ";                                    // lea

    var lea = MemScanner(moduleData, pattern) - 0x76;
    var relativeOffset = BitConverter.ToInt32(moduleData, lea + 0x3);
    var absoluteOffset = lea + relativeOffset + 7;
    var absoluteAddress = IntPtr.Add(proc.MainModule.BaseAddress, absoluteOffset);

    byte[] pointerBytes = new byte[8];
    ReadProcessMemory(proc.Handle, absoluteAddress, pointerBytes, (uint)8, out _);
    return (IntPtr)BitConverter.ToUInt64(pointerBytes, 0);
}

Dictionary<string, int> cameraOffsets = new Dictionary<string, int>
{
    { "Distance", 0x114 },
    { "MinDistance", 0x118 },
    { "MaxDistance", 0x11C },
    { "FoV", 0x120 },
    { "MinFoV", 0x124 },
    { "MaxFoV", 0x128 },
    { "InterpDistance", 0x17C },
    { "SavedDistance", 0x188 },
};

Dictionary<string, float> camaraDefaultParams = new Dictionary<string, float>
{
    { "MinDistance", 2.5f },
    { "MaxDistance", 20.0f },
    { "MinFoV", 0.68f },
    { "MaxFoV", 0.78f },
};

float GetCamaraParam(Process proc, string param)
{
    if (cameraOffsets.ContainsKey(param))
    {
        IntPtr address = IntPtr.Add(GetCameraAddress(proc), cameraOffsets[param]);
        return Read<float>(proc, address);
    }
    else
    {
        TriggernometryHelpers.Log(Triggernometry.RealPlugin.DebugLevelEnum.Error, $"错误的相机参数 ({param})。");
        return 0.0f;
    }
}

void SetCamaraParam(Process proc, string param, float newValue)
{
    if (cameraOffsets.ContainsKey(param))
    {
        IntPtr address = IntPtr.Add(GetCameraAddress(proc), cameraOffsets[param]);
        Write<float>(proc, address, newValue);
        TriggernometryHelpers.Log(Triggernometry.RealPlugin.DebugLevelEnum.Custom, $"成功设置相机参数 {param} = {newValue}");
    }
    else
    {
        TriggernometryHelpers.Log(Triggernometry.RealPlugin.DebugLevelEnum.Error, $"错误的相机参数 ({param})。");
    }
}

void ResetCamara(Process proc)
{
    try 
    {
        foreach (string param in camaraDefaultParams.Keys)
        {
            Write<float>(proc, IntPtr.Add(GetCameraAddress(proc), cameraOffsets[param]), camaraDefaultParams[param]);
            TriggernometryHelpers.Log(Triggernometry.RealPlugin.DebugLevelEnum.Custom, $"成功设置相机参数 {param} = {camaraDefaultParams[param]}");
        }
    }
    catch
    {
        TriggernometryHelpers.Log(Triggernometry.RealPlugin.DebugLevelEnum.Error, $"重设相机参数失败。");
    }
}

TriggernometryHelpers.Delegates["GetCamaraParam"] = new Func<Process, string, float>(GetCamaraParam);
TriggernometryHelpers.Delegates["SetCamaraParam"] = new Action<Process, string, float>(SetCamaraParam);
TriggernometryHelpers.Delegates["ResetCamara"] = new Action<Process>(ResetCamara);
#endregion

#region 实体坐标
void SetEntityCoordination(Process proc, IntPtr entityAddress, float? x, float? y, float? z, float? h)
{
    IntPtr addrX = entityAddress + 0xB0;
    IntPtr addrY = entityAddress + 0xB8;
    IntPtr addrZ = entityAddress + 0xB4;
    IntPtr addrH = entityAddress + 0xC0;
    IntPtr addrModel = (IntPtr)BitConverter.ToInt64(ReadBytes(proc, entityAddress + 0x100, (uint)8), 0);
    IntPtr addrMX = addrModel + 0x50;
    IntPtr addrMY = addrModel + 0x58;
    IntPtr addrMZ = addrModel + 0x54;
    // IntPtr ??? = addrModel + 0x64;
    // IntPtr ??? = addrModel + 0x6C;

    if (x != null)
    {
        Write<float>(proc, addrX, (float)x);
        Write<float>(proc, addrMX, (float)x);
    }
    if (y != null)
    {
        Write<float>(proc, addrY, (float)y);
        Write<float>(proc, addrMY, (float)y);
    }
    if (z != null)
    {
        Write<float>(proc, addrZ, (float)z);
        Write<float>(proc, addrMZ, (float)z);
    }
    if (h != null)
    {
        Write<float>(proc, addrH, (float)h);
    }
}
TriggernometryHelpers.Delegates["SetEntityCoordination"] = new Action<Process, IntPtr, float?, float?, float?, float?>(SetEntityCoordination);

void Teleport(object o, string str)
{
    var tpParams = Triggernometry.Context.SplitArguments(str + ":::", allowEmptyList: true, separator: ":");
    float? x = null, y = null, z = null, h = null;
    IntPtr myAddress = (IntPtr)Int64.Parse(TriggernometryHelpers.EvaluateStringExpression("${_me.address}"));
    if (tpParams[0] != "") { x = float.Parse(tpParams[1], NumberStyles.Float, CultureInfo.InvariantCulture); }
    if (tpParams[1] != "") { y = float.Parse(tpParams[2], NumberStyles.Float, CultureInfo.InvariantCulture); }
    if (tpParams[2] != "") { z = float.Parse(tpParams[3], NumberStyles.Float, CultureInfo.InvariantCulture); }
    if (tpParams[3] != "") { h = float.Parse(tpParams[4], NumberStyles.Float, CultureInfo.InvariantCulture); }

    SetEntityCoordination(GetProcess(), myAddress, x, y, z, h);
}

TriggernometryHelpers.Plugin.RegisterNamedCallback("teleport", new Action<object, string>(Teleport), null);
#endregion
