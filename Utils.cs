using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net.Sockets;
using System.Threading;
using System.Net;
using System.IO;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Diagnostics;

namespace Hypervisor_Manager
{
    public static class Utils
    {
        public static void RC4(ref byte[] Data, byte[] Key)
        {
            try
            {
                byte num;
                int num2;
                byte[] buffer = new byte[0x100];
                byte[] buffer2 = new byte[0x100];
                for (num2 = 0; num2 < 0x100; num2++)
                {
                    buffer[num2] = (byte)num2;
                    buffer2[num2] = Key[num2 % Key.GetLength(0)];
                }
                int index = 0;
                for (num2 = 0; num2 < 0x100; num2++)
                {
                    index = ((index + buffer[num2]) + buffer2[num2]) % 0x100;
                    num = buffer[num2];
                    buffer[num2] = buffer[index];
                    buffer[index] = num;
                }
                num2 = index = 0;
                for (int i = 0; i < Data.GetLength(0); i++)
                {
                    num2 = (num2 + 1) % 0x100;
                    index = (index + buffer[num2]) % 0x100;
                    num = buffer[num2];
                    buffer[num2] = buffer[index];
                    buffer[index] = num;
                    int num5 = (buffer[num2] + buffer[index]) % 0x100;
                    Data[i] = (byte)(Data[i] ^ buffer[num5]);
                }
            }
            catch (Exception ex)
            {
                Console.Write(ex.Message);
                return;
            }
        }

        public static string BytesToHexString(byte[] Buffer)
        {
            try
            {
                string str = "";
                for (int i = 0; i < Buffer.Length; i++)
                {
                    str = str + Buffer[i].ToString("X2");
                }
                return str;
            }
            catch (Exception ex)
            {
                Console.Write(ex.Message);
            }
            return "";
        }
    }
}
