<#
.SYNOPSIS
Sends a file to a paired Bluetooth device using OBEX Object Push.

.DESCRIPTION
Uses Windows Winsock Bluetooth APIs and an embedded OBEX implementation. No
external modules or libraries are required. The receiving device must be
paired, in range, and advertise the Bluetooth OBEX Object Push service.

.PARAMETER Path
The file to send.

.PARAMETER DeviceAddress
The receiver's 12-digit Bluetooth address, with or without ':' or '-' separators.

.PARAMETER TimeoutMilliseconds
The send and receive timeout. The default is 30000 milliseconds.

.EXAMPLE
.\Send-BluetoothFile.ps1 -Path .\photo.jpg -DeviceAddress 'AA:BB:CC:DD:EE:FF'
pwsh -NoProfile -Command 'try { & "./Send-BluetoothFile.ps1" -Path "./file.pdf" -DeviceAddress "04:CF:4B:7F:B8:E9" } catch { $_ | Format-List * -Force; exit 1 }'

#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string] $Path,

    [Parameter(Mandatory, Position = 1)]
    [ValidatePattern('^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$|^[0-9A-Fa-f]{12}$')]
    [string] $DeviceAddress,

    [ValidateRange(1000, 300000)]
    [int] $TimeoutMilliseconds = 30000
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') {
    throw 'This script requires Windows Bluetooth and Winsock APIs.'
}

if (-not ('BluetoothObexUploaderV2.Client' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace BluetoothObexUploaderV2
{
    public sealed class UploadResult
    {
        public string DeviceAddress { get; internal set; }
        public string FileName { get; internal set; }
        public long BytesSent { get; internal set; }
        public uint RfcommChannel { get; internal set; }
    }

    public static class Client
    {
        private const int AF_BTH = 32;
        private const int SOCK_STREAM = 1;
        private const int BTHPROTO_RFCOMM = 3;
        private const int SOL_SOCKET = 0xFFFF;
        private const int SO_SNDTIMEO = 0x1005;
        private const int SO_RCVTIMEO = 0x1006;
        private const uint NS_BTH = 16;
        private const uint LUP_RETURN_ADDR = 0x0100;
        private const uint LUP_FLUSHCACHE = 0x2000;
        private const int WSAEFAULT = 10014;
        private const byte ObexSuccess = 0xA0;
        private const byte ObexContinue = 0x90;

        private static readonly Guid ObexObjectPushService =
            new Guid("00001105-0000-1000-8000-00805F9B34FB");

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        private struct WsaData
        {
            public ushort Version;
            public ushort HighVersion;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 257)]
            public string Description;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 129)]
            public string SystemStatus;
            public ushort MaximumSockets;
            public ushort MaximumUdpDatagram;
            public IntPtr VendorInfo;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct SockAddrBth
        {
            public ushort AddressFamily;
            public ulong BluetoothAddress;
            public Guid ServiceClassId;
            public uint Port;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WsaQuerySet
        {
            public uint Size;
            public IntPtr ServiceInstanceName;
            public IntPtr ServiceClassId;
            public IntPtr Version;
            public IntPtr Comment;
            public uint NameSpace;
            public IntPtr NameSpaceProviderId;
            public IntPtr Context;
            public uint NumberOfProtocols;
            public IntPtr Protocols;
            public IntPtr QueryString;
            public uint NumberOfCsAddresses;
            public IntPtr CsAddresses;
            public uint OutputFlags;
            public IntPtr Blob;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SocketAddress
        {
            public IntPtr Address;
            public int AddressLength;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct CsAddrInfo
        {
            public SocketAddress LocalAddress;
            public SocketAddress RemoteAddress;
            public int SocketType;
            public int Protocol;
        }

        [DllImport("Ws2_32.dll", CharSet = CharSet.Ansi)]
        private static extern int WSAStartup(ushort requestedVersion, out WsaData data);

        [DllImport("Ws2_32.dll")]
        private static extern int WSACleanup();

        [DllImport("Ws2_32.dll", SetLastError = true)]
        private static extern IntPtr socket(int addressFamily, int socketType, int protocol);

        [DllImport("Ws2_32.dll", SetLastError = true)]
        private static extern int connect(IntPtr socketHandle, ref SockAddrBth address, int addressLength);

        [DllImport("Ws2_32.dll", SetLastError = true)]
        private static extern int send(IntPtr socketHandle, byte[] buffer, int length, int flags);

        [DllImport("Ws2_32.dll", SetLastError = true)]
        private static extern int recv(IntPtr socketHandle, byte[] buffer, int length, int flags);

        [DllImport("Ws2_32.dll", SetLastError = true)]
        private static extern int setsockopt(
            IntPtr socketHandle,
            int level,
            int optionName,
            ref int optionValue,
            int optionLength);

        [DllImport("Ws2_32.dll", SetLastError = true)]
        private static extern int closesocket(IntPtr socketHandle);

        [DllImport("Ws2_32.dll", CharSet = CharSet.Unicode)]
        private static extern int WSAAddressToStringW(
            ref SockAddrBth address,
            int addressLength,
            IntPtr protocolInfo,
            StringBuilder addressString,
            ref int addressStringLength);

        [DllImport("Ws2_32.dll", CharSet = CharSet.Unicode)]
        private static extern int WSALookupServiceBeginW(
            ref WsaQuerySet restrictions,
            uint controlFlags,
            out IntPtr lookupHandle);

        [DllImport("Ws2_32.dll", CharSet = CharSet.Unicode)]
        private static extern int WSALookupServiceNextW(
            IntPtr lookupHandle,
            uint controlFlags,
            ref uint bufferLength,
            IntPtr results);

        [DllImport("Ws2_32.dll")]
        private static extern int WSALookupServiceEnd(IntPtr lookupHandle);

        [DllImport("Ws2_32.dll")]
        private static extern int WSAGetLastError();

        public static UploadResult SendFile(string path, string deviceAddress, int timeoutMilliseconds)
        {
            string fullPath = Path.GetFullPath(path);
            string fileName = Path.GetFileName(fullPath);
            ulong address = ParseBluetoothAddress(deviceAddress);
            WsaData wsaData;
            int startupResult = WSAStartup(0x0202, out wsaData);
            if (startupResult != 0)
                throw new Win32Exception(startupResult, "Could not initialize Winsock");

            try
            {
                IntPtr socketHandle = socket(AF_BTH, SOCK_STREAM, BTHPROTO_RFCOMM);
                if (socketHandle == new IntPtr(-1))
                    ThrowSocketError("Could not create a Bluetooth socket");

                try
                {
                    SetTimeout(socketHandle, SO_SNDTIMEO, timeoutMilliseconds);
                    SetTimeout(socketHandle, SO_RCVTIMEO, timeoutMilliseconds);

                    uint rfcommChannel = FindObjectPushChannel(address);

                    SockAddrBth socketAddress = new SockAddrBth
                    {
                        AddressFamily = AF_BTH,
                        BluetoothAddress = address,
                        ServiceClassId = Guid.Empty,
                        Port = rfcommChannel
                    };

                    if (connect(socketHandle, ref socketAddress, Marshal.SizeOf(typeof(SockAddrBth))) != 0)
                    {
                        int error = WSAGetLastError();
                        if (error == 10049)
                        {
                            throw new Win32Exception(
                                error,
                                "The SDP-discovered OBEX RFCOMM channel is no longer available. " +
                                "Keep the receiver in 'Receive files' mode and retry");
                        }
                        ThrowSocketError("Could not connect to the device's OBEX Object Push service");
                    }

                    byte[] connectionResponse = Exchange(
                        socketHandle,
                        new byte[] { 0x80, 0x00, 0x07, 0x10, 0x00, 0xFF, 0xFF });
                    RequireResponse(connectionResponse, ObexSuccess, "OBEX connection was rejected");
                    if (connectionResponse.Length < 7)
                        throw new InvalidDataException("The device returned an invalid OBEX connection response.");

                    int maximumPacketLength = ReadUInt16(connectionResponse, 5);
                    if (maximumPacketLength < 255)
                        throw new InvalidDataException("The device negotiated an invalid OBEX packet size.");

                    byte[] connectionId = FindConnectionId(connectionResponse);
                    long bytesSent = PutFile(socketHandle, fullPath, fileName, maximumPacketLength, connectionId);

                    try
                    {
                        byte[] disconnectPacket = BuildPacket(0x81, connectionId, null, 0, 0);
                        Exchange(socketHandle, disconnectPacket);
                    }
                    catch
                    {
                        // The upload has completed; a peer closing early must not mark it failed.
                    }

                    return new UploadResult
                    {
                        DeviceAddress = FormatBluetoothAddress(address),
                        FileName = fileName,
                        BytesSent = bytesSent,
                        RfcommChannel = rfcommChannel
                    };
                }
                finally
                {
                    closesocket(socketHandle);
                }
            }
            finally
            {
                WSACleanup();
            }
        }

        public static uint[] FindObjectPushChannels(string deviceAddress)
        {
            WsaData wsaData;
            int startupResult = WSAStartup(0x0202, out wsaData);
            if (startupResult != 0)
                throw new Win32Exception(startupResult, "Could not initialize Winsock");

            try
            {
                return FindObjectPushChannels(ParseBluetoothAddress(deviceAddress));
            }
            finally
            {
                WSACleanup();
            }
        }

        private static uint FindObjectPushChannel(ulong address)
        {
            uint[] channels = FindObjectPushChannels(address);
            if (channels.Length == 0)
            {
                throw new InvalidOperationException(
                    "The device is not advertising the OBEX Object Push service. On a Windows " +
                    "receiver, open Bluetooth File Transfer and select 'Receive files', then retry.");
            }
            return channels[0];
        }

        private static uint[] FindObjectPushChannels(ulong address)
        {
            string context = AddressToString(address);
            IntPtr serviceClassId = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Guid)));
            IntPtr contextPointer = Marshal.StringToHGlobalUni(context);
            IntPtr lookupHandle = IntPtr.Zero;
            try
            {
                Marshal.StructureToPtr(ObexObjectPushService, serviceClassId, false);
                WsaQuerySet restrictions = new WsaQuerySet
                {
                    Size = (uint)Marshal.SizeOf(typeof(WsaQuerySet)),
                    ServiceClassId = serviceClassId,
                    NameSpace = NS_BTH,
                    Context = contextPointer
                };

                if (WSALookupServiceBeginW(
                    ref restrictions,
                    LUP_RETURN_ADDR | LUP_FLUSHCACHE,
                    out lookupHandle) != 0)
                {
                    int error = WSAGetLastError();
                    if (error == 10108)
                        return new uint[0];
                    ThrowSocketError("Could not query the device's OBEX Object Push service");
                }

                return ReadRfcommChannels(lookupHandle);
            }
            finally
            {
                if (lookupHandle != IntPtr.Zero)
                    WSALookupServiceEnd(lookupHandle);
                Marshal.FreeHGlobal(contextPointer);
                Marshal.FreeHGlobal(serviceClassId);
            }
        }

        private static uint[] ReadRfcommChannels(IntPtr lookupHandle)
        {
            uint bufferLength = 4096;
            IntPtr buffer = Marshal.AllocHGlobal((int)bufferLength);
            try
            {
                while (true)
                {
                    Marshal.WriteInt32(buffer, Marshal.SizeOf(typeof(WsaQuerySet)));
                    if (WSALookupServiceNextW(
                        lookupHandle,
                        LUP_RETURN_ADDR,
                        ref bufferLength,
                        buffer) == 0)
                    {
                        break;
                    }

                    int error = WSAGetLastError();
                    if (error != WSAEFAULT)
                        throw new Win32Exception(error, "Could not read the OBEX service discovery result");

                    Marshal.FreeHGlobal(buffer);
                    buffer = Marshal.AllocHGlobal((int)bufferLength);
                }

                WsaQuerySet result = (WsaQuerySet)Marshal.PtrToStructure(
                    buffer,
                    typeof(WsaQuerySet));
                int itemSize = Marshal.SizeOf(typeof(CsAddrInfo));
                System.Collections.Generic.List<uint> channels =
                    new System.Collections.Generic.List<uint>();

                for (uint index = 0; index < result.NumberOfCsAddresses; index++)
                {
                    IntPtr itemPointer = new IntPtr(result.CsAddresses.ToInt64() + index * itemSize);
                    CsAddrInfo item = (CsAddrInfo)Marshal.PtrToStructure(
                        itemPointer,
                        typeof(CsAddrInfo));
                    if (item.RemoteAddress.Address == IntPtr.Zero ||
                        item.RemoteAddress.AddressLength < Marshal.SizeOf(typeof(SockAddrBth)))
                    {
                        continue;
                    }

                    SockAddrBth remoteAddress = (SockAddrBth)Marshal.PtrToStructure(
                        item.RemoteAddress.Address,
                        typeof(SockAddrBth));
                    if (remoteAddress.AddressFamily == AF_BTH &&
                        remoteAddress.Port >= 1 && remoteAddress.Port <= 30 &&
                        !channels.Contains(remoteAddress.Port))
                    {
                        channels.Add(remoteAddress.Port);
                    }
                }

                return channels.ToArray();
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static string AddressToString(ulong address)
        {
            SockAddrBth socketAddress = new SockAddrBth
            {
                AddressFamily = AF_BTH,
                BluetoothAddress = address,
                ServiceClassId = Guid.Empty,
                Port = 0
            };
            int length = 128;
            StringBuilder result = new StringBuilder(length);
            if (WSAAddressToStringW(
                ref socketAddress,
                Marshal.SizeOf(typeof(SockAddrBth)),
                IntPtr.Zero,
                result,
                ref length) != 0)
            {
                ThrowSocketError("Could not format the Bluetooth address for service discovery");
            }
            return result.ToString();
        }

        private static long PutFile(
            IntPtr socketHandle,
            string path,
            string fileName,
            int maximumPacketLength,
            byte[] connectionId)
        {
            byte[] nameHeader = BuildNameHeader(fileName);
            FileInfo file = new FileInfo(path);
            if (file.Length > UInt32.MaxValue)
                throw new NotSupportedException("OBEX Object Push supports files up to 4 GiB.");

            byte[] lengthHeader = new byte[5];
            lengthHeader[0] = 0xC3;
            WriteUInt32(lengthHeader, 1, (uint)file.Length);
            byte[] initialHeaders = Combine(connectionId, nameHeader, lengthHeader);

            long totalSent = 0;
            bool firstPacket = true;
            using (FileStream input = File.OpenRead(path))
            {
                while (firstPacket || totalSent < file.Length)
                {
                    byte[] headers = firstPacket ? initialHeaders : connectionId;
                    int capacity = maximumPacketLength - 6 - headers.Length;
                    if (capacity <= 0)
                        throw new InvalidDataException("The file name is too long for the negotiated OBEX packet size.");

                    int requested = (int)Math.Min((long)capacity, file.Length - totalSent);
                    byte[] body = new byte[requested];
                    int bodyLength = ReadChunk(input, body);
                    bool isFinal = totalSent + bodyLength == file.Length;
                    byte opcode = isFinal ? (byte)0x82 : (byte)0x02;
                    byte bodyHeader = isFinal ? (byte)0x49 : (byte)0x48;
                    byte[] packet = BuildPutPacket(opcode, headers, bodyHeader, body, bodyLength);
                    byte[] response = Exchange(socketHandle, packet);
                    RequireResponse(
                        response,
                        isFinal ? ObexSuccess : ObexContinue,
                        "The device rejected the file transfer");

                    totalSent += bodyLength;
                    firstPacket = false;
                }
            }

            return totalSent;
        }

        private static byte[] BuildPutPacket(
            byte opcode,
            byte[] headers,
            byte bodyHeader,
            byte[] body,
            int bodyLength)
        {
            int packetLength = 3 + headers.Length + 3 + bodyLength;
            byte[] packet = new byte[packetLength];
            packet[0] = opcode;
            WriteUInt16(packet, 1, packetLength);
            Buffer.BlockCopy(headers, 0, packet, 3, headers.Length);
            int bodyOffset = 3 + headers.Length;
            packet[bodyOffset] = bodyHeader;
            WriteUInt16(packet, bodyOffset + 1, bodyLength + 3);
            if (bodyLength > 0)
                Buffer.BlockCopy(body, 0, packet, bodyOffset + 3, bodyLength);
            return packet;
        }

        private static byte[] BuildPacket(
            byte opcode,
            byte[] headers,
            byte[] body,
            int bodyOffset,
            int bodyLength)
        {
            int headersLength = headers == null ? 0 : headers.Length;
            byte[] packet = new byte[3 + headersLength + bodyLength];
            packet[0] = opcode;
            WriteUInt16(packet, 1, packet.Length);
            if (headersLength > 0)
                Buffer.BlockCopy(headers, 0, packet, 3, headersLength);
            if (bodyLength > 0)
                Buffer.BlockCopy(body, bodyOffset, packet, 3 + headersLength, bodyLength);
            return packet;
        }

        private static byte[] Exchange(IntPtr socketHandle, byte[] request)
        {
            SendAll(socketHandle, request);
            byte[] prefix = ReceiveExact(socketHandle, 3);
            int packetLength = ReadUInt16(prefix, 1);
            if (packetLength < 3)
                throw new InvalidDataException("The device returned an invalid OBEX packet.");

            byte[] response = new byte[packetLength];
            Buffer.BlockCopy(prefix, 0, response, 0, 3);
            if (packetLength > 3)
            {
                byte[] remainder = ReceiveExact(socketHandle, packetLength - 3);
                Buffer.BlockCopy(remainder, 0, response, 3, remainder.Length);
            }
            return response;
        }

        private static void SendAll(IntPtr socketHandle, byte[] data)
        {
            int offset = 0;
            while (offset < data.Length)
            {
                byte[] remaining = data;
                if (offset != 0)
                {
                    remaining = new byte[data.Length - offset];
                    Buffer.BlockCopy(data, offset, remaining, 0, remaining.Length);
                }

                int sent = send(socketHandle, remaining, remaining.Length, 0);
                if (sent <= 0)
                    ThrowSocketError("Bluetooth send failed");
                offset += sent;
            }
        }

        private static byte[] ReceiveExact(IntPtr socketHandle, int length)
        {
            byte[] result = new byte[length];
            int offset = 0;
            while (offset < length)
            {
                byte[] chunk = new byte[length - offset];
                int received = recv(socketHandle, chunk, chunk.Length, 0);
                if (received == 0)
                    throw new EndOfStreamException("The Bluetooth device closed the connection.");
                if (received < 0)
                    ThrowSocketError("Bluetooth receive failed");
                Buffer.BlockCopy(chunk, 0, result, offset, received);
                offset += received;
            }
            return result;
        }

        private static byte[] FindConnectionId(byte[] connectResponse)
        {
            int offset = 7;
            while (offset < connectResponse.Length)
            {
                byte headerId = connectResponse[offset];
                int headerType = headerId & 0xC0;
                if (headerId == 0xCB && offset + 5 <= connectResponse.Length)
                {
                    byte[] header = new byte[5];
                    Buffer.BlockCopy(connectResponse, offset, header, 0, 5);
                    return header;
                }

                int headerLength;
                if (headerType == 0x00 || headerType == 0x40)
                {
                    if (offset + 3 > connectResponse.Length)
                        break;
                    headerLength = ReadUInt16(connectResponse, offset + 1);
                }
                else
                {
                    headerLength = headerType == 0x80 ? 2 : 5;
                }

                if (headerLength <= 0 || offset + headerLength > connectResponse.Length)
                    break;
                offset += headerLength;
            }
            return new byte[0];
        }

        private static byte[] BuildNameHeader(string fileName)
        {
            byte[] text = Encoding.BigEndianUnicode.GetBytes(fileName + "\0");
            byte[] header = new byte[text.Length + 3];
            header[0] = 0x01;
            WriteUInt16(header, 1, header.Length);
            Buffer.BlockCopy(text, 0, header, 3, text.Length);
            return header;
        }

        private static byte[] Combine(params byte[][] arrays)
        {
            int length = 0;
            foreach (byte[] array in arrays)
                length += array == null ? 0 : array.Length;
            byte[] result = new byte[length];
            int offset = 0;
            foreach (byte[] array in arrays)
            {
                if (array == null)
                    continue;
                Buffer.BlockCopy(array, 0, result, offset, array.Length);
                offset += array.Length;
            }
            return result;
        }

        private static int ReadChunk(Stream input, byte[] buffer)
        {
            int offset = 0;
            while (offset < buffer.Length)
            {
                int read = input.Read(buffer, offset, buffer.Length - offset);
                if (read == 0)
                    break;
                offset += read;
            }
            return offset;
        }

        private static ulong ParseBluetoothAddress(string value)
        {
            string normalized = value.Replace(":", "").Replace("-", "");
            return Convert.ToUInt64(normalized, 16);
        }

        private static string FormatBluetoothAddress(ulong address)
        {
            string compact = address.ToString("X12");
            string[] parts = new string[6];
            for (int index = 0; index < parts.Length; index++)
                parts[index] = compact.Substring(index * 2, 2);
            return String.Join(":", parts);
        }

        private static void SetTimeout(IntPtr socketHandle, int option, int milliseconds)
        {
            int value = milliseconds;
            if (setsockopt(socketHandle, SOL_SOCKET, option, ref value, sizeof(int)) != 0)
                ThrowSocketError("Could not configure the Bluetooth socket timeout");
        }

        private static void RequireResponse(byte[] response, byte expected, string message)
        {
            if (response.Length == 0 || response[0] != expected)
            {
                string code = response.Length == 0 ? "none" : "0x" + response[0].ToString("X2");
                throw new InvalidOperationException(message + " (OBEX response " + code + ").");
            }
        }

        private static int ReadUInt16(byte[] buffer, int offset)
        {
            return (buffer[offset] << 8) | buffer[offset + 1];
        }

        private static void WriteUInt16(byte[] buffer, int offset, int value)
        {
            buffer[offset] = (byte)(value >> 8);
            buffer[offset + 1] = (byte)value;
        }

        private static void WriteUInt32(byte[] buffer, int offset, uint value)
        {
            buffer[offset] = (byte)(value >> 24);
            buffer[offset + 1] = (byte)(value >> 16);
            buffer[offset + 2] = (byte)(value >> 8);
            buffer[offset + 3] = (byte)value;
        }

        private static void ThrowSocketError(string message)
        {
            int error = WSAGetLastError();
            throw new Win32Exception(error, message + " (Winsock error " + error + ")");
        }
    }
}
'@
}

$resolvedPath = (Resolve-Path -LiteralPath $Path).ProviderPath
[BluetoothObexUploaderV2.Client]::SendFile($resolvedPath, $DeviceAddress, $TimeoutMilliseconds)