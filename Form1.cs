using System;
using System.Windows.Forms;
using System.IO;
using System.Security.Cryptography;
using System.Diagnostics;

namespace Hypervisor_Manager
{
    public partial class Form1 : Form
    {
        private static byte[] OfflineHypervisor;
        private static byte[] DumpedHypervisor;
        private static byte[] UnknownData = new byte[0x20] { 0x64, 0xFA, 0x1A, 0xC2, 0x0F, 0xD7, 0x58, 0x07, 0xCA, 0xE6, 0x74, 0xBA, 0xA3, 0xB4, 0x78, 0x7F, 0xD1, 0xE3, 0xB3, 0x3A, 0x6C, 0x1E, 0xF7, 0x70, 0x5F, 0x6D, 0xE9, 0x3B, 0xB6, 0xC0, 0xDC, 0x71 };
        private static byte[] FBLKey = new byte[0x10] { 0xDD, 0x88, 0xAD, 0x0C, 0x9E, 0xD6, 0x69, 0xE7, 0xB5, 0x67, 0x94, 0xFB, 0x68, 0x56, 0x3E, 0xFA };

        // Array of salts
        public static byte[][] saltsArray = new byte[256][];

        // Current supported kernel
        private static readonly short supportedKernel = 17559;

        // File names
        private static readonly string HV_DUMP = "HV_Dumped.bin";
        private static readonly string HV_CLEAN = "HV_Cleaned.bin";
        private static readonly string HV_BASE = "HV_Base.bin";
        private static readonly string HV_SALTS = "HV_SALTS.bin";
        private static readonly string HV_STATIC_ECC = "ECC_555.bin";
        private static readonly string ENC_CODE_CHAL = "EncryptedCodeChallenge.bin";
        private static readonly string DEC_CODE_CHAL = "DecryptedCodeChallenge.bin";

        // File locations
        private static string HypervisorLoc = null;
        private static string OutputLoc = null;

        public Form1()
        {
            InitializeComponent();

        }

        private void Form1_Load(object sender, EventArgs e)
        {
            // Set text to supported version
            this.Text = string.Format("Hypervisor Manager - {0}", supportedKernel);

            // Setup some strings
            HypervisorLoc = string.Format("Hypervisor\\{0}\\", supportedKernel);
            OutputLoc = string.Format("Output\\{0}\\", supportedKernel);

            // Make sure the hypervisor folder exists
            if (!System.IO.Directory.Exists("Hypervisor\\"))
            {
                Console.WriteLine("Failed to find Hypervisor files. Does Hypervisor folder exist?");
                groupBox1.Enabled = false;
                button4.Enabled = false;
            }

            // Disable Update functions if no update folder found
            if (!System.IO.Directory.Exists("Update\\"))
            {
                Console.WriteLine("Failed to find Update files. Does Update folder & files exist?");
                groupBox3.Enabled = false;
            }

            // Create the output folder
            if (!System.IO.Directory.Exists("Output\\") || !System.IO.Directory.Exists(string.Format("Output\\{0}\\", supportedKernel)))
            {
                System.IO.Directory.CreateDirectory(OutputLoc);
            }
        }

        private static byte[] Calculate100F0(bool saveDigest)
        {
            byte[] ComputedHash = new byte[0x10];
            byte[] cleanEccData = File.ReadAllBytes(HypervisorLoc + HV_STATIC_ECC);
            OfflineHypervisor = File.ReadAllBytes(HypervisorLoc + HV_BASE);

            SHA1Managed F0Hash = new SHA1Managed();
            for (int index = 0; index < 6; ++index)
            {
                byte[] Addresses = BitConverter.GetBytes(BitConverter.ToUInt32(OfflineHypervisor, 0x10878 + index * 8));
                Array.Reverse(Addresses);
                byte[] Sizes = BitConverter.GetBytes(BitConverter.ToUInt32(OfflineHypervisor, 0x10878 + index * 8 + 4));
                Array.Reverse(Sizes);

                uint iAddr = BitConverter.ToUInt32(Addresses, 0);
                uint iSizes = BitConverter.ToUInt32(Sizes, 0);
                uint uAddr = (uint)(iAddr + 0x7F & 0xFFFFFFFFFFFFFF80);
                uint uSize = iSizes & 0xFFFFFF80;
                if (uAddr < uSize)
                {
                    if (index != 5)
                    {
                        F0Hash.TransformBlock(cleanEccData, (int)(uAddr >> 6), (int)uSize - (int)uAddr >> 6, null, 0);
                    }
                    else
                    {
                        F0Hash.TransformFinalBlock(cleanEccData, (int)(uAddr >> 6), (int)uSize - (int)uAddr >> 6);
                        Buffer.BlockCopy(F0Hash.Hash, 0, ComputedHash, 0, 0x10);
                        F0Hash.Dispose();
                    }
                }
            }
            if (saveDigest)
                File.WriteAllBytes(OutputLoc + "100F0.bin", ComputedHash);

            Console.WriteLine("100F0 Hash: {0}", Utils.BytesToHexString(ComputedHash));
            return ComputedHash;

        }

        private void CleanHypervisor()
        {
            byte[] CleanedHypervisor = new byte[0x40000];
            OfflineHypervisor = File.ReadAllBytes(HypervisorLoc + HV_BASE);
            DumpedHypervisor = File.ReadAllBytes(HypervisorLoc + HV_DUMP);

            Buffer.BlockCopy(DumpedHypervisor, 0, CleanedHypervisor, 0, 0x40000);
            Buffer.BlockCopy(OfflineHypervisor, 0x8, CleanedHypervisor, 0x88, 0xC);
            Buffer.BlockCopy(OfflineHypervisor, 0x34, CleanedHypervisor, 0x34, 0xC);
            Buffer.BlockCopy(OfflineHypervisor, 0x70, CleanedHypervisor, 0x70, 0x4);
            Buffer.BlockCopy(OfflineHypervisor, 0x78, CleanedHypervisor, 0x78, 0xFF88);
            Buffer.BlockCopy(OfflineHypervisor, 0x10008, CleanedHypervisor, 0x10008, 0x18);
            Buffer.BlockCopy(OfflineHypervisor, 0x10130, CleanedHypervisor, 0x10130, 0x6190);
            Buffer.BlockCopy(UnknownData, 0, CleanedHypervisor, 0x10FF8, 0x20);
            Buffer.BlockCopy(OfflineHypervisor, 0x11018, CleanedHypervisor, 0x11018, 0x52BB);
            Buffer.BlockCopy(OfflineHypervisor, 0x16F00, CleanedHypervisor, 0x16F00, 0x29100);

            // If we want to calculate and add in the 100F0 hash
            if (checkBox1.Checked)
            {
                if (File.Exists(HypervisorLoc + HV_STATIC_ECC))
                {
                    Buffer.BlockCopy(Calculate100F0(false), 0, CleanedHypervisor, 0x100F0, 0x10);
                }
                else
                {
                    Console.WriteLine("Failed to find" + HypervisorLoc + HV_STATIC_ECC);
                }
            }

            File.WriteAllBytes(OutputLoc + HV_CLEAN, CleanedHypervisor);
        }

        private static byte[] DecryptChallengePayload(bool SaveFile)
        {
            if (File.Exists(HypervisorLoc + ENC_CODE_CHAL))
            {
                byte[] Enc_Payload = File.ReadAllBytes(HypervisorLoc + ENC_CODE_CHAL);
                byte[] Data = new byte[Enc_Payload.Length - 0x20];
                Buffer.BlockCopy(Enc_Payload, 0x20, Data, 0, Enc_Payload.Length - 0x20);
                byte[] PayloadHash = new byte[0x10];
                Buffer.BlockCopy(Enc_Payload, 0x10, PayloadHash, 0, 0x10);
                HMACSHA1 FBLSHA = new HMACSHA1(FBLKey);
                FBLSHA.ComputeHash(PayloadHash);
                Buffer.BlockCopy(FBLSHA.Hash, 0, PayloadHash, 0, 0x10);
                FBLSHA.Dispose();
                Utils.RC4(ref Data, PayloadHash);
                Buffer.BlockCopy(Data, 0, Enc_Payload, 0x20, Data.Length);
                if (SaveFile)
                    File.WriteAllBytes(OutputLoc + DEC_CODE_CHAL, Enc_Payload);

                return Enc_Payload;
            }
            else
            {
                Console.WriteLine("Failed to find" + HypervisorLoc + ENC_CODE_CHAL);
            }

            return null;
        }

        private static void OutputDigestRanges()
        {
            byte[] DecChallenge = DecryptChallengePayload(false);
            long[] Addresses = new long[7];

            StreamWriter sw = File.CreateText(OutputLoc + "DigestData.txt");

            if (DecChallenge.Length > 0x3B0)
            {
                Console.WriteLine("Code Challenge Hash 1 Ranges:");
                sw.WriteLine("Code Challenge Hash 1 Ranges:");
                for (int i = 0; i < 7; ++i)
                {
                    byte[] bAddresses = BitConverter.GetBytes(BitConverter.ToInt64(DecChallenge, 0x3B0 + i * 8));
                    Array.Reverse(bAddresses);
                    Addresses[i] = BitConverter.ToInt64(bAddresses, 0);
                    Console.WriteLine("HV DEC Address: 0x{0:X}, Size: 0x{1:X}", (Addresses[i] >> 16 & 0xFFFFF), (Addresses[i] & 0xFFFF));
                    sw.WriteLine("HV DEC Address: 0x{0:X}, Size: 0x{1:X}", (Addresses[i] >> 16 & 0xFFFFF), (Addresses[i] & 0xFFFF));
                }
            }
            long[] Adresses = new long[13];
            if (DecChallenge.Length > 0x3B0)
            {
                Console.WriteLine("\n");
                sw.WriteLine("\n");
                Console.WriteLine("Code Challenge Hash 2 Ranges:");
                sw.WriteLine("Code Challenge Hash 2 Ranges:");
                for (int i = 0; i < 13; ++i)
                {
                    byte[] bAddresses = BitConverter.GetBytes(BitConverter.ToInt64(DecChallenge, 0x348 + i * 8));
                    Array.Reverse(bAddresses);
                    Adresses[i] = BitConverter.ToInt64(bAddresses, 0);
                    if ((Adresses[i] & 0x8000) != 0)
                    {
                        Console.WriteLine("ECC Address: 0x{0:X}, Size: 0x{1:X}", (Adresses[i] >> 22 & 0xFFF), ((Adresses[i] & 0x3FF) << 1));
                        sw.WriteLine("ECC Address: 0x{0:X}, Size: 0x{1:X}", (Adresses[i] >> 22 & 0xFFF), ((Adresses[i] & 0x3FF) << 1));
                    }
                    else if ((Adresses[i] & 0x7F) >= 16)
                    {
                        Console.WriteLine("HV ENC Address: 0x{0:X}, Size: 0x{1:X}", (Adresses[i] >> 16 & 0x3FFFF), (Adresses[i] & 0x7F));
                        sw.WriteLine("HV ENC Address: 0x{0:X}, Size: 0x{1:X}", (Adresses[i] >> 16 & 0x3FFFF), (Adresses[i] & 0x7F));
                    }
                    else
                    {
                        Console.WriteLine("HV DEC Address:  0x{0:X}, Size: 0x{1:X}", (Adresses[i] >> 16), (Adresses[i] & 0x7F));
                        sw.WriteLine("HV DEC Address:  0x{0:X}, Size: 0x{1:X}", (Adresses[i] >> 16), (Adresses[i] & 0x7F));
                    }
                }
            }
            Console.WriteLine("\n");
            sw.WriteLine("\n");
            sw.Close();
        }

        private static void Output100F0Ranges()
        {
            OfflineHypervisor = File.ReadAllBytes(HypervisorLoc + HV_BASE);

            StreamWriter sw = File.CreateText(OutputLoc + "100F0Ranges.txt");

            Console.WriteLine("100F0 hash data:");
            sw.WriteLine("100F0 hash data:");
            for (int index = 0; index < 6; ++index)
            {
                byte[] Addresses = BitConverter.GetBytes(BitConverter.ToUInt32(OfflineHypervisor, 0x10878 + index * 8));
                Array.Reverse(Addresses);
                byte[] Sizes = BitConverter.GetBytes(BitConverter.ToUInt32(OfflineHypervisor, 0x10878 + index * 8 + 4));
                Array.Reverse(Sizes);
                uint iAddr = BitConverter.ToUInt32(Addresses, 0);
                uint iSizes = BitConverter.ToUInt32(Sizes, 0);
                uint uAddr = (uint)(iAddr + 0x7F & 0xFFFFFFFFFFFFFF80);
                uint uSize = iSizes & 0xFFFFFF80;
                if (uAddr < uSize)
                {
                    Console.WriteLine("ECC Address: 0x{0:X}, Size: 0x{1:X} | HV Address: 0x{2:X}, Size: 0x{3:X}", (uAddr >> 6), (uSize - uAddr >> 6), ((uAddr >> 6) * 0x40), (uSize - uAddr));
                    sw.WriteLine("ECC Address: 0x{0:X}, Size: 0x{1:X} | HV Address: 0x{2:X}, Size: 0x{3:X}", (uAddr >> 6), (uSize - uAddr >> 6), ((uAddr >> 6) * 0x40), (uSize - uAddr));
                }
            }

            Console.WriteLine("\n");
            sw.WriteLine("\n");
            sw.Close();
        }

        private static void GetNewHypervisorAndKernel()
        {
            if (!File.Exists("Update\\xboxupd.bin"))
                return;

            Console.WriteLine("xboxupd.bin found!");
            if (File.Exists("Update\\xboxkrnl.1888.exe"))
            {
                Console.WriteLine("xboxkrnl.1888.exe found!");
                if (File.Exists("Update\\krnlupdate.exe"))
                {
                    Console.WriteLine("krnlupdate.exe found!");
                    byte[] bKernelVersion = BitConverter.GetBytes(BitConverter.ToInt16(File.ReadAllBytes("Update\\xboxupd.bin"), 2));
                    Array.Reverse(bKernelVersion);
                    short kernelVersion = BitConverter.ToInt16(bKernelVersion, 0);
                    Process process = new Process();
                    process.StartInfo = new ProcessStartInfo("cmd")
                    {
                        UseShellExecute = false,
                        RedirectStandardInput = true,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true,
                        WorkingDirectory = Directory.GetCurrentDirectory() + "\\Update\\",
                        Arguments = string.Format("/c \"{0}\"", string.Format("krnlupdate.exe xboxupd.bin xboxkrnl.1888.exe xboxkrnl.{0}.exe", kernelVersion))
                    };
                    Console.WriteLine("Starting kernel update!");
                    process.Start();
                    string end = process.StandardOutput.ReadToEnd();
                    bool flag = end.Contains("Updated kernel version");
                    Console.WriteLine(end);
                    Console.WriteLine("Kernel update success, grabbing new base hypervisor & kernel!");
                    if (!flag)
                        return;

                    byte[] baseHypervisor = new byte[0x40000];
                    byte[] newKernel = File.ReadAllBytes(string.Format("Update\\xboxkrnl.{0}.exe", kernelVersion));
                    byte[] kernelWithoutHv = new byte[newKernel.Length - 0x40000];
                    Buffer.BlockCopy(newKernel, 0, baseHypervisor, 0, 0x40000);
                    Buffer.BlockCopy(newKernel, 0x40000, kernelWithoutHv, 0, newKernel.Length - 0x40000);
                    File.WriteAllBytes(OutputLoc + HV_BASE, baseHypervisor);
                    File.WriteAllBytes(string.Format("Output\\{0}\\Kernel{1}.bin", supportedKernel, kernelVersion), kernelWithoutHv);
                    File.Delete(string.Format("Update\\xboxkrnl.{0}.exe", kernelVersion));
                    Console.WriteLine("Saved new hypervisor & kernel!");
                    Console.WriteLine("\n");
                }
                else
                    Console.WriteLine("Failed to find Update\\krnlupdate.exe!");
            }
            else
                Console.WriteLine("Failed to find Update\\xboxkrnl.1888.exe!");
        }

        private static void LoadSaltArray()
        {
            try
            {
                byte[] saltBuffer = File.ReadAllBytes(HypervisorLoc + HV_SALTS);

                for (int x = 0; x < saltsArray.Length; x++)
                {
                    saltsArray[x] = new byte[0x10];
                }

                for (int i = 0; i < 256; i++)
                {
                    Buffer.BlockCopy(saltBuffer, i * 0x10, saltsArray[i], 0, 0x10);
                }
            }
            catch (Exception ex)
            {
                Console.Write(ex.Message);
                return;
            }
        }

        private static byte[] FindSaltFile(byte[] clientHvSalt, int keySelect)
        {
            try
            {
                byte[] saltDump = new byte[0x40];

                if (clientHvSalt == null)
                    return null;

                saltDump = File.ReadAllBytes("Seeds\\" + keySelect + "\\Salts\\0x" + Utils.BytesToHexString(clientHvSalt) + ".bin");

                return saltDump;
            }
            catch (Exception ex)
            {
                Console.Write(ex.Message);
                return null;
            }
        }

        private static void GenerateHash1Results()
        {
            byte[] Salt = new byte[0x10];
            byte[] HashResult = new byte[0x6];
            byte[] CleanDecHV = File.ReadAllBytes(HypervisorLoc + HV_CLEAN);

            StreamWriter sw = File.CreateText(OutputLoc + "Hashes.txt");

            for (int i = 0; i < 256; i++)
            {
                Buffer.BlockCopy(saltsArray[i], 0, Salt, 0, 0x10);

                SHA1Managed Hash = new SHA1Managed();
                Hash.TransformBlock(Salt, 0, 0x10, null, 0);
                Hash.TransformBlock(CleanDecHV, 0x34, 0x40, null, 0);
                Hash.TransformBlock(CleanDecHV, 0x78, 0xFF88, null, 0);
                Hash.TransformBlock(CleanDecHV, 0x100C0, 0x40, null, 0);
                Hash.TransformBlock(CleanDecHV, 0x10350, 0x5F70, null, 0);
                Hash.TransformBlock(CleanDecHV, 0x16EA0, 0x9160, null, 0);
                Hash.TransformBlock(CleanDecHV, 0x20000, 0xFFFF, null, 0);
                Hash.TransformFinalBlock(CleanDecHV, 0x30000, 0xFFFF);

                Buffer.BlockCopy(Hash.Hash, 0xE, HashResult, 0, 0x6);
                Hash.Dispose();

                Console.WriteLine("Salt: {0}", Utils.BytesToHexString(saltsArray[i]));
                Console.WriteLine("Computed Hash: {0}", Utils.BytesToHexString(HashResult));
                Console.WriteLine("\n");

                sw.WriteLine("Salt: {0}", Utils.BytesToHexString(saltsArray[i]));
                sw.WriteLine("Computed Hash: {0}", Utils.BytesToHexString(HashResult));
                sw.WriteLine("\n");
            }

            sw.Close();
        }

        private static void GenerateHash2Results()
        {
            byte[] saltDump = new byte[0x40];
            byte[] eccSalt = new byte[0x2];
            byte[] HashResult = new byte[0x14];

            byte[] CleanDecHV = File.ReadAllBytes(HypervisorLoc + "Data\\" + HV_CLEAN);
            byte[] CleanEncHV = File.ReadAllBytes(string.Format("Hypervisor\\{0}\\Data\\HV_ENC.bin", supportedKernel));
            byte[] CleanEccData = File.ReadAllBytes(string.Format("Hypervisor\\{0}\\Data\\HV_ECC.bin", supportedKernel));
            byte[] EncryptionKeys = File.ReadAllBytes(string.Format("Hypervisor\\{0}\\Data\\HV_KEYS.bin", supportedKernel));

            for (int i = 0; i < 256; i++)
            {
                saltDump = FindSaltFile(saltsArray[i], 0);
                if (saltDump == null)
                {
                    Console.WriteLine("Failed to find salt file for {0}", Utils.BytesToHexString(saltsArray[i]));
                    continue;
                }

                Buffer.BlockCopy(saltDump, 0x20, eccSalt, 0, 0x2);

                SHA1Managed Hash = new SHA1Managed();
                Hash.TransformBlock(eccSalt, 0, 2, null, 0);
                Hash.TransformBlock(CleanDecHV, 0x34, 0xC, null, 0);
                Hash.TransformBlock(CleanEncHV, 0x40, 0x30, null, 0);
                Hash.TransformBlock(CleanDecHV, 0x70, 0x4, null, 0);
                Hash.TransformBlock(CleanDecHV, 0x78, 0x8, null, 0);
                Hash.TransformBlock(CleanEccData, 0x2, 0x3FE, null, 0);
                Hash.TransformBlock(CleanEncHV, 0x100C0, 0x40, null, 0);
                Hash.TransformBlock(CleanEncHV, 0x10350, 0x30, null, 0);
                Hash.TransformBlock(CleanEccData, 0x40E, 0x17C, null, 0);
                Hash.TransformBlock(CleanEncHV, 0x16280, 0x40, null, 0);
                Hash.TransformBlock(CleanEncHV, 0x16EA0, 0x60, null, 0);
                Hash.TransformBlock(CleanEccData, 0x5BC, 0x244, null, 0);
                Hash.TransformBlock(CleanEccData, 0x800, 0x400, null, 0);
                Hash.TransformFinalBlock(CleanEccData, 0xC00, 0x400);

                Buffer.BlockCopy(Hash.Hash, 0, HashResult, 0, 0x14);
                Hash.Dispose();

                Console.WriteLine("Salt: {0}", Utils.BytesToHexString(saltsArray[i]));
                Console.WriteLine("ECC Salt: 0x{0}", Utils.BytesToHexString(eccSalt));
                Console.WriteLine("Encryption Keys: {0}", Utils.BytesToHexString(EncryptionKeys));
                Console.WriteLine("Computed Hash: 0x{0}", Utils.BytesToHexString(HashResult));
                Console.WriteLine("\n");

            }
        }

        private static void GeneratePairData(byte[] HvSalt, byte[] DecHV, byte[] EncHV, byte[] EccData, byte[] EccSalt, byte[] EncryptionKeys, byte[] ExecAddress)
        {
            byte[] PairData = new byte[0x4F];

            for (int i = 0; i < 256; i++)
            {
                SHA1Managed Hash1 = new SHA1Managed();
                Hash1.TransformBlock(HvSalt, 0, 0x10, null, 0);
                Hash1.TransformBlock(DecHV, 0x34, 0x40, null, 0);
                Hash1.TransformBlock(DecHV, 0x78, 0xFF88, null, 0);
                Hash1.TransformBlock(DecHV, 0x100C0, 0x40, null, 0);
                Hash1.TransformBlock(DecHV, 0x10350, 0x5F70, null, 0);
                Hash1.TransformBlock(DecHV, 0x16EA0, 0x9160, null, 0);
                Hash1.TransformBlock(DecHV, 0x20000, 0xFFFF, null, 0);
                Hash1.TransformFinalBlock(DecHV, 0x30000, 0xFFFF);

                Buffer.BlockCopy(Hash1.Hash, 0xE, PairData, 0, 0x6);
                Hash1.Dispose();

                SHA1Managed Hash2 = new SHA1Managed();
                Hash2.TransformBlock(EccSalt, 0, 2, null, 0);
                Hash2.TransformBlock(DecHV, 0x34, 0xC, null, 0);
                Hash2.TransformBlock(EncHV, 0x40, 0x30, null, 0);
                Hash2.TransformBlock(DecHV, 0x70, 0x4, null, 0);
                Hash2.TransformBlock(DecHV, 0x78, 0x8, null, 0);
                Hash2.TransformBlock(EccData, 0x2, 0x3FE, null, 0);
                Hash2.TransformBlock(EncHV, 0x100C0, 0x40, null, 0);
                Hash2.TransformBlock(EncHV, 0x10350, 0x30, null, 0);
                Hash2.TransformBlock(EccData, 0x40E, 0x17C, null, 0);
                Hash2.TransformBlock(EncHV, 0x16280, 0x40, null, 0);
                Hash2.TransformBlock(EncHV, 0x16EA0, 0x60, null, 0);
                Hash2.TransformBlock(EccData, 0x5BC, 0x244, null, 0);
                Hash2.TransformBlock(EccData, 0x800, 0x400, null, 0);
                Hash2.TransformFinalBlock(EccData, 0xC00, 0x400);

                Buffer.BlockCopy(Hash2.Hash, 0, PairData, 0x7, 0x14);
                Hash2.Dispose();
            }
        }

        private void button1_Click(object sender, EventArgs e)
        {
            CleanHypervisor();
            Console.WriteLine("Cleaned hypervisor successfully!");
        }

        private void button2_Click(object sender, EventArgs e)
        {
            byte[] DecPayload = DecryptChallengePayload(true);
            Console.WriteLine("Decrypted challenge successfully!");
        }

        private void button3_Click(object sender, EventArgs e)
        {
            OutputDigestRanges();
            Console.WriteLine("Outputed digest data successfully!");
        }

        private void button4_Click(object sender, EventArgs e)
        {
            Output100F0Ranges();
            Console.WriteLine("Outputed 100F0 digest data successfully!");
        }

        private void button5_Click(object sender, EventArgs e)
        {
            GetNewHypervisorAndKernel();
            Console.WriteLine("Extracted new hypervisor and kernel successfully!");
        }

        private void button6_Click(object sender, EventArgs e)
        {
            Calculate100F0(true);
            Console.WriteLine("Generated 100F0 hash successfully!");
        }

        private void button7_Click(object sender, EventArgs e)
        {
            LoadSaltArray();
            GenerateHash1Results();
            Console.WriteLine("Generated 256 hashes successfully!");
        }

        private void button8_Click(object sender, EventArgs e)
        {
            int Numberofpairs = 5;
            for (int i = 0; i < Numberofpairs; i++)
            {
                byte[] PairData = new byte[0x4F];
                string PairLocation = string.Format("Seeds\\{0}", i);

                byte[] HV_ENC = File.ReadAllBytes(PairLocation + "HV_Enc.bin");
                byte[] HV_DEC = File.ReadAllBytes(HypervisorLoc + HV_CLEAN);
                byte[] HV_ECC = File.ReadAllBytes(PairLocation + "cache.bin");
                byte[] HV_KEY = File.ReadAllBytes(PairLocation + "Key.bin");


                for (int saltIndex = 0; saltIndex < 256; saltIndex++)
                {
                    byte[] DumpedData = File.ReadAllBytes(PairLocation + "\\Salts\\0x" + Utils.BytesToHexString(saltsArray[saltIndex]) + ".bin");
                    byte[] HashResult = new byte[0x6];

                    SHA1Managed Hash = new SHA1Managed();
                    Hash.TransformBlock(saltsArray[saltIndex], 0, 0x10, null, 0);
                    Hash.TransformBlock(HV_DEC, 0x34, 0x40, null, 0);
                    Hash.TransformBlock(HV_DEC, 0x78, 0xFF88, null, 0);
                    Hash.TransformBlock(HV_DEC, 0x100C0, 0x40, null, 0);
                    Hash.TransformBlock(HV_DEC, 0x10350, 0x5F70, null, 0);
                    Hash.TransformBlock(HV_DEC, 0x16EA0, 0x9160, null, 0);
                    Hash.TransformBlock(HV_DEC, 0x20000, 0xFFFF, null, 0);
                    Hash.TransformFinalBlock(HV_DEC, 0x30000, 0xFFFF);

                    Buffer.BlockCopy(Hash.Hash, 0xE, HashResult, 0, 0x6);
                    Hash.Dispose();

                    // Copy the 1st hash to our pair data
                    Buffer.BlockCopy(HashResult, 0, PairData, 0, 0x6);

                    // Copy the execution address
                    Buffer.BlockCopy(DumpedData, 0x30, PairData, 0x4E, 0x2);

                }
            }
        }
    }
}
