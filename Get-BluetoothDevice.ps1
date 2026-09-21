<#
.SYNOPSIS
Lists Bluetooth devices known to Windows and their addresses.

.DESCRIPTION
Uses the native Windows Bluetooth APIs through embedded C#. By default, the
script returns cached paired, remembered, and connected devices. Use Discover
to perform an inquiry and include nearby unknown devices.

.PARAMETER Discover
Performs a Bluetooth inquiry in addition to returning cached devices.

.PARAMETER InquiryTimeout
The inquiry duration multiplier, from 1 through 48. Each unit is approximately
1.28 seconds. The default is 8 (approximately 10.24 seconds).

.EXAMPLE
.\Get-BluetoothDevice.ps1

.EXAMPLE
.\Get-BluetoothDevice.ps1 -Discover | Select-Object Name, Address
#>
[CmdletBinding()]
param(
    [switch] $Discover,

    [ValidateRange(1, 48)]
    [byte] $InquiryTimeout = 8
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') {
    throw 'This script requires the Windows Bluetooth APIs.'
}

if (-not ('BluetoothDeviceEnumerator.Client' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace BluetoothDeviceEnumerator
{
    public sealed class Device
    {
        public string Name { get; internal set; }
        public string Address { get; internal set; }
        public bool Connected { get; internal set; }
        public bool Remembered { get; internal set; }
        public bool Authenticated { get; internal set; }
        public DateTime? LastSeen { get; internal set; }
        public DateTime? LastUsed { get; internal set; }
    }

    public static class Client
    {
        private const int ErrorNoMoreItems = 259;
        private const int ErrorNotFound = 1168;

        [StructLayout(LayoutKind.Sequential)]
        private struct BluetoothDeviceSearchParams
        {
            public int Size;
            [MarshalAs(UnmanagedType.Bool)]
            public bool ReturnAuthenticated;
            [MarshalAs(UnmanagedType.Bool)]
            public bool ReturnRemembered;
            [MarshalAs(UnmanagedType.Bool)]
            public bool ReturnUnknown;
            [MarshalAs(UnmanagedType.Bool)]
            public bool ReturnConnected;
            [MarshalAs(UnmanagedType.Bool)]
            public bool IssueInquiry;
            public byte TimeoutMultiplier;
            public IntPtr RadioHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SystemTime
        {
            public ushort Year;
            public ushort Month;
            public ushort DayOfWeek;
            public ushort Day;
            public ushort Hour;
            public ushort Minute;
            public ushort Second;
            public ushort Milliseconds;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct BluetoothDeviceInfo
        {
            public int Size;
            public ulong Address;
            public uint ClassOfDevice;
            [MarshalAs(UnmanagedType.Bool)]
            public bool Connected;
            [MarshalAs(UnmanagedType.Bool)]
            public bool Remembered;
            [MarshalAs(UnmanagedType.Bool)]
            public bool Authenticated;
            public SystemTime LastSeen;
            public SystemTime LastUsed;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 248)]
            public string Name;
        }

        [DllImport("Bthprops.cpl", SetLastError = true)]
        private static extern IntPtr BluetoothFindFirstDevice(
            ref BluetoothDeviceSearchParams searchParams,
            ref BluetoothDeviceInfo deviceInfo);

        [DllImport("Bthprops.cpl", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool BluetoothFindNextDevice(
            IntPtr findHandle,
            ref BluetoothDeviceInfo deviceInfo);

        [DllImport("Bthprops.cpl")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool BluetoothFindDeviceClose(IntPtr findHandle);

        public static Device[] Find(bool discover, byte inquiryTimeout)
        {
            BluetoothDeviceSearchParams searchParams = new BluetoothDeviceSearchParams
            {
                Size = Marshal.SizeOf(typeof(BluetoothDeviceSearchParams)),
                ReturnAuthenticated = true,
                ReturnRemembered = true,
                ReturnUnknown = discover,
                ReturnConnected = true,
                IssueInquiry = discover,
                TimeoutMultiplier = inquiryTimeout,
                RadioHandle = IntPtr.Zero
            };
            BluetoothDeviceInfo deviceInfo = CreateDeviceInfo();
            IntPtr findHandle = BluetoothFindFirstDevice(ref searchParams, ref deviceInfo);
            if (findHandle == IntPtr.Zero)
            {
                int error = Marshal.GetLastWin32Error();
                if (error == ErrorNoMoreItems || error == ErrorNotFound)
                    return new Device[0];
                throw new Win32Exception(error, "Could not enumerate Bluetooth devices");
            }

            List<Device> devices = new List<Device>();
            try
            {
                while (true)
                {
                    devices.Add(ConvertDevice(deviceInfo));
                    deviceInfo = CreateDeviceInfo();
                    if (!BluetoothFindNextDevice(findHandle, ref deviceInfo))
                    {
                        int error = Marshal.GetLastWin32Error();
                        if (error != ErrorNoMoreItems)
                            throw new Win32Exception(error, "Could not continue enumerating Bluetooth devices");
                        break;
                    }
                }
            }
            finally
            {
                BluetoothFindDeviceClose(findHandle);
            }

            return devices.ToArray();
        }

        private static BluetoothDeviceInfo CreateDeviceInfo()
        {
            return new BluetoothDeviceInfo
            {
                Size = Marshal.SizeOf(typeof(BluetoothDeviceInfo))
            };
        }

        private static Device ConvertDevice(BluetoothDeviceInfo deviceInfo)
        {
            return new Device
            {
                Name = deviceInfo.Name,
                Address = FormatAddress(deviceInfo.Address),
                Connected = deviceInfo.Connected,
                Remembered = deviceInfo.Remembered,
                Authenticated = deviceInfo.Authenticated,
                LastSeen = ConvertTime(deviceInfo.LastSeen),
                LastUsed = ConvertTime(deviceInfo.LastUsed)
            };
        }

        private static DateTime? ConvertTime(SystemTime value)
        {
            if (value.Year == 0 || value.Month == 0 || value.Day == 0)
                return null;

            try
            {
                return new DateTime(
                    value.Year,
                    value.Month,
                    value.Day,
                    value.Hour,
                    value.Minute,
                    value.Second,
                    value.Milliseconds,
                    DateTimeKind.Local);
            }
            catch (ArgumentOutOfRangeException)
            {
                return null;
            }
        }

        private static string FormatAddress(ulong address)
        {
            string compact = address.ToString("X12");
            string[] parts = new string[6];
            for (int index = 0; index < parts.Length; index++)
                parts[index] = compact.Substring(index * 2, 2);
            return String.Join(":", parts);
        }
    }
}
'@
}

[BluetoothDeviceEnumerator.Client]::Find($Discover.IsPresent, $InquiryTimeout) |
    Sort-Object Name, Address