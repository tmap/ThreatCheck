using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;

namespace ThreatCheck
{
    class Defender
    {
        byte[] FileBytes;
        string FilePath;
        bool Malicious = false;
        bool Complete = false;

        public Defender(byte[] file)
        {
            FileBytes = file;
        }

        public void AnalyzeFile()
        {
            if (!Directory.Exists(@"C:\Temp"))
            {
#if DEBUG
                CustomConsole.WriteDebug(@"C:\Temp doesn't exist. Creating it...");
#endif
                Directory.CreateDirectory(@"C:\Temp");
            }

            FilePath = Path.Combine(@"C:\Temp", "file.exe");
            File.WriteAllBytes(FilePath, FileBytes);

            var status = Scan(FilePath);

            if (status.Result == ScanResult.NoThreatFound)
            {
                CustomConsole.WriteOutput("No threat found!");
                return;
            }
            else
            {
                Malicious = true;
            }

            CustomConsole.WriteOutput($"Target file size: {FileBytes.Length} bytes");
            CustomConsole.WriteOutput("Analyzing...");

            var splitArray = new byte[FileBytes.Length / 2];
            Buffer.BlockCopy(FileBytes, 0, splitArray, 0, FileBytes.Length / 2);
            var lastgood = 0;

            while (!Complete)
            {
#if DEBUG
                CustomConsole.WriteDebug($"Testing {splitArray.Length} bytes");
#endif
                File.WriteAllBytes(FilePath, splitArray);
                var detectionStatus = Scan(FilePath);

                if (detectionStatus.Result == ScanResult.ThreatFound)
                {
#if DEBUG
                    CustomConsole.WriteDebug("Threat found, splitting");
#endif
                    var tmpArray = HalfSplitter(splitArray, lastgood);
                    Array.Resize(ref splitArray, tmpArray.Length);
                    Array.Copy(tmpArray, splitArray, tmpArray.Length);
                }
                else if (detectionStatus.Result == ScanResult.NoThreatFound)
                {
#if DEBUG
                    CustomConsole.WriteDebug("No threat found, increasing size");
#endif
                    lastgood = splitArray.Length;
                    var tmpArray = Overshot(FileBytes, splitArray.Length);
                    Array.Resize(ref splitArray, tmpArray.Length);
                    Buffer.BlockCopy(tmpArray, 0, splitArray, 0, tmpArray.Length);
                }
            }
        }

        public DefenderScanResult Scan(string file, bool getsig = false)
        {
            var result = new DefenderScanResult();

            if (!File.Exists(file))
            {
                result.Result = ScanResult.FileNotFound;
                return result;
            }

            var process = new Process();
            var mpcmdrun = new ProcessStartInfo(@"C:\Program Files\Windows Defender\MpCmdRun.exe")
            {
                Arguments = $"-Scan -ScanType 3 -File \"{file}\" -DisableRemediation -Trace -Level 0x10",
                CreateNoWindow = true,
                ErrorDialog = false,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };

            process.StartInfo = mpcmdrun;
            process.Start();
            process.WaitForExit(30000); //Wait 30s

            if (!process.HasExited)
            {
                process.Kill();
                result.Result = ScanResult.Timeout;
                return result;
            }

            if (getsig)
            {
                string stdout;
                string sigName;

                while ((stdout = process.StandardOutput.ReadLine()) != null)
                {
                    if (stdout.Contains("Threat  "))
                    {
                        string[] sig = stdout.Split(' ');
                        sigName = sig[19]; // Lazy way to get the signature name from MpCmdRun
                        result.Signature = sigName;
                        break;
                    }
                }
            }

            switch (process.ExitCode)
            {
                case 0:
                    result.Result = ScanResult.NoThreatFound;
                    break;
                case 2:
                    result.Result = ScanResult.ThreatFound;
                    break;
                default:
                    result.Result = ScanResult.Error;
                    break;
            }

            return result;
        }

        byte[] HalfSplitter(byte[] originalarray, int lastgood)
        {
            var splitArray = new byte[(originalarray.Length - lastgood) / 2 + lastgood];

            if (originalarray.Length == splitArray.Length + 1)
            {
                var result = Scan(FilePath, true);
                var msg = string.Format("Identified end of bad bytes at offset 0x{0:X}", originalarray.Length);
                var sig = string.Format("File matched signature {0}", result.Signature);

                CustomConsole.WriteThreat(msg);
                CustomConsole.WriteThreat(sig);

                byte[] offendingBytes = new byte[256];

                if (originalarray.Length < 256)
                {
                    Array.Resize(ref offendingBytes, originalarray.Length);
                    Buffer.BlockCopy(originalarray, originalarray.Length, offendingBytes, 0, originalarray.Length);
                }
                else
                {
                    Buffer.BlockCopy(originalarray, originalarray.Length - 256, offendingBytes, 0, 256);
                }

                Helpers.HexDump(offendingBytes);

#if DEBUG
                CustomConsole.WriteDebug($"Removing {FilePath}");
#endif
                File.Delete(@"C:\Temp\testfile.exe");
                Complete = true;
            }

            Array.Copy(originalarray, splitArray, splitArray.Length);
            return splitArray;
        }

        byte[] Overshot(byte[] originalarray, int splitarraysize)
        {
            var newsize = (originalarray.Length - splitarraysize) / 2 + splitarraysize;

            if (newsize.Equals(originalarray.Length - 1))
            {
                Complete = true;

                if (Malicious)
                {
                    CustomConsole.WriteError("File is malicious, but couldn't identify bad bytes");
                }
            }

            var newarray = new byte[newsize];
            Buffer.BlockCopy(originalarray, 0, newarray, 0, newarray.Length);

            return newarray;
        }
    }

    public class DefenderScanResult
    {
        public ScanResult Result { get; set; }
        public string Signature { get; set; }
    }

    public enum ScanResult
    {
        [Description("No threat found")]
        NoThreatFound,
        [Description("Threat found")]
        ThreatFound,
        [Description("The file could not be found")]
        FileNotFound,
        [Description("Timeout")]
        Timeout,
        [Description("Error")]
        Error
    }
}