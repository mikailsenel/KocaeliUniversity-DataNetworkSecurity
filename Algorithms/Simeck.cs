using Algorithms.Common.Abstract;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace Algorithms
{
    public class Simeck : EncryptionAlgorithm
    {
        const int BLOCK_SIZE = 128; // blok boyutu (bit)
        private const int WORDSIZE = 16; //byte
        const int NUM_ROUNDS = 44;

        public Simeck(string text) : base(text)
        {

        }

        protected override void Initial(string text, string _key)
        {

            byte[] plainText;

            if (text.Equals("-"))
                plainText = new byte[WORDSIZE] { 0x75, 0x6E, 0x64, 0x20, 0x6C, 0x69, 0x6B, 0x65, 0x75, 0x6E, 0x64, 0x20, 0x6C, 0x69, 0x6B, 0x65 };
            else
                plainText = Encoding.ASCII.GetBytes(text);

            byte[] key = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0A, 0x0B, 0x10, 0x11, 0x12, 0x13, 0x18, 0x19, 0x1A, 0x1B };

            byte[] chiperText = new byte[plainText.Length % WORDSIZE == 0 ? plainText.Length : plainText.Length + (WORDSIZE - (plainText.Length % WORDSIZE))];

            plainText.CopyTo(chiperText, 0);


            for (int i = 0; i < (chiperText.Length / WORDSIZE); i++)
            {
                byte[] tmp = new byte[WORDSIZE];

                Array.Copy(chiperText, i * WORDSIZE, tmp, 0, WORDSIZE);

                tmp = Encrypt(i + 1, tmp, key);

                Array.Copy(tmp, 0, chiperText, i * WORDSIZE, WORDSIZE);
            }

            AddStep("Düz metin      : " + BitConverter.ToString(plainText), toBinaryString(plainText));

            AddStep("Anahtar        : " + BitConverter.ToString(key), toBinaryString(key));

            AddStep("Şifreli metin  : " + BitConverter.ToString(chiperText), toBinaryString(chiperText));


        }

        private static string print_chipers(byte[] state, byte[] keyCells)
        {
            return "S = " + BitConverter.ToString(state.Cast<byte>().ToArray()) + (keyCells == null ? "" : " - TK = " + BitConverter.ToString(keyCells.Cast<byte>().ToArray()));
        }


        public static void clearlast0(ref Byte[] chiperText)
        {
            if (chiperText.Length == 0)
                return;

            int clearcount = 0;

            for (int i = (chiperText.Length - 1); i >= (chiperText.Length - WORDSIZE); i--)
            {
                if (chiperText[i] == 0x00)
                    clearcount++;
                else
                    break;
            }

            if (clearcount > 0)
                Array.Resize<Byte>(ref chiperText, chiperText.Length - clearcount);
        }





        // Encrypt a 64-bit plaintext with a 128-bit key
        public byte[] Encrypt(int partno, byte[] bplaintext, byte[] masterKey)
        {

            uint[] ciphertext = byteToUints(bplaintext, 0);
            uint[] keys = byteToUints(masterKey, 0);

            uint temp;

            uint constant = 0xFFFFFFFC;
            ulong sequence = 0x938BCA3083F;

            AddStep("Encryption Part (" + partno.ToString("D2") + ") - Başlangıç  " + print_chipers(bplaintext, null), toBinaryString(bplaintext));

            for (int i = 0; i < NUM_ROUNDS; i++)
            {
                ROUND64(keys[0], ref ciphertext[1], ref ciphertext[0]);
                ROUND64(keys[0], ref ciphertext[3], ref ciphertext[2]);
                constant &= 0xFFFFFFFC;
                constant |= (uint)(sequence & 1);
                sequence >>= 1;
                ROUND64(constant, ref keys[1], ref keys[0]);
                // rotate the LFSR of keys
                temp = keys[1];
                keys[1] = keys[2];
                keys[2] = keys[3];
                keys[3] = temp;


                AddStep("Encryption Part (" + partno.ToString("D2") + ") Round : (" + i.ToString("D2") + ") " + print_chipers(uinttoByte(ciphertext), null), toBinaryString(uinttoByte(ciphertext)));

            }

            return uinttoByte(ciphertext);

        }

        public byte[] GetBigEndianBytes(UInt32 val, bool isLittleEndian)
        {
            UInt32 bigEndian = val;
            if (isLittleEndian)
            {
                bigEndian = (val & 0x000000FFU) << 24 | (val & 0x0000FF00U) << 8 |
                     (val & 0x00FF0000U) >> 8 | (val & 0xFF000000U) >> 24;
            }
            return BitConverter.GetBytes(bigEndian);
        }

        private byte[] uinttoByte(uint[] deger)
        {
            byte[] tmpreturn = new byte[deger.Length * sizeof(uint)];

            for (int i = 0; i < deger.Length; i++)
            {
                byte[] barray = System.BitConverter.GetBytes(deger[i]);
                for (int j = 0; j < barray.Length; j++)
                {
                    tmpreturn[i * sizeof(uint) + j] = barray[j];
                }
            }

            return tmpreturn;
        }

        public string toBinaryString(byte[,] data)
        {
            return toBinaryString(data.Cast<byte>().ToArray());
        }

        public string toBinaryString(byte[] data)
        {
            StringBuilder binaryString = new StringBuilder();
            foreach (byte r in data)
            {
                string binary = Convert.ToString(r, 2).PadLeft(8, '0');
                binaryString.Append(binary + " ");
            }
            return binaryString.ToString();
        }



        // Bir bayt dizisini bir ulong dizisine dönüştüren işlev
        public uint[] byteToUints(byte[] bytes, int minBytes)
        {

            // Diziyi, 4 baytlık (32 bitlik uint) grupların oluşturduğu başka bir diziye geçiriyorum   
            int cant = (bytes.Length % 4 == 0) ? bytes.Length : bytes.Length + (4 - bytes.Length % 4);
            if (cant < minBytes) cant = minBytes;
            byte[] b = new byte[cant];
            bytes.CopyTo(b, 0);

            Console.WriteLine();


            uint[] c = new uint[b.Length / 4];

            for (int i = 0; i < c.Length; i++)
                c[i] = BitConverter.ToUInt32(b, i * 4);

            return c;
        }

        // Left rotate a 32-bit integer by r bits
        private uint LROT32(uint x, int r)
        {
            return (x << r) | (x >> (32 - r));
        }

        // Perform one round of encryption
        private void ROUND64(uint key, ref uint lft, ref uint rgt)
        {
            uint tmp = lft;
            lft = (lft & LROT32(lft, 5)) ^ LROT32(lft, 1) ^ rgt ^ key;
            rgt = tmp;
        }




    }

}
