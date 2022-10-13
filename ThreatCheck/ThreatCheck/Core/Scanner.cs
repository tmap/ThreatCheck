using System;

namespace ThreatCheck
{
    class Scanner
    {
        public static bool Malicious = false;
        public static bool Complete = false;

        public virtual byte[] HalfSplitter(byte[] originalarray, int lastgood)
        {
            var splitArray = new byte[(originalarray.Length - lastgood) / 2 + lastgood];

            if (originalarray.Length == splitArray.Length + 1)
            {
                var msg = string.Format("!den71f13d 3nd 0f b4d by735 at 0ffs37 Ox{O:X}", originalarray.Length);

                CustomConsole.WriteThreat(msg);

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
                Complete = true;
            }

            Array.Copy(originalarray, splitArray, splitArray.Length);
            return splitArray;
        }

        public virtual byte[] Overshot(byte[] originalarray, int splitarraysize)
        {
            var newsize = (originalarray.Length - splitarraysize) / 2 + splitarraysize;

            if (newsize.Equals(originalarray.Length - 1))
            {
                Complete = true;

                if (Malicious)
                {
                    CustomConsole.WriteError("F1l3 1s m4l1c10u5, bu7 c0uldn'7 1d3nt1fy b4d by735");
                }
            }

            var newarray = new byte[newsize];
            Buffer.BlockCopy(originalarray, 0, newarray, 0, newarray.Length);

            return newarray;
        }
    }
}
