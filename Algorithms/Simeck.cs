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
        public Simeck(string text) : base(text)
        {
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
            byte[] tmpreturn=new byte[deger.Length * sizeof(uint)];

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


        public string toBinaryString(byte[] data)
        {
            StringBuilder binaryString = new StringBuilder();
            foreach (byte r in data)
            {
                string binary = Convert.ToString(r, 2).PadLeft(8, '0');
                binaryString.Append(binary+" ");
            }
            return binaryString.ToString();
        }

        const int BLOCK_SIZE = 128; // blok boyutu (bit)

        protected override void Initial(string text, string key)
        {

            byte[] bufferPlain = Encoding.ASCII.GetBytes(text);
            
            //uint[] text64 = { 0x20646e75, 0x656b696c, 0x20646e75, 0x656b696c };
            uint[] text64 = byteToUints(Encoding.ASCII.GetBytes(text), 0);


            // girdilerin uzunluklarını kontrol et
            if (bufferPlain.Length != BLOCK_SIZE / 8)
                throw new ArgumentException("Text boyutu " + BLOCK_SIZE + " bit uzunluğunda olmalı");

            
            uint[] key128 =
                {
                    0x03020100,
                    0x0b0a0908,
                    0x13121110,
                    0x1b1a1918
                };

            
            AddStep("Düz metin: ", BitConverter.ToString(uinttoByte(text64)));                         
            AddStep("Düz metin: ", toBinaryString(uinttoByte(text64)));
            
            AddStep("Anahtar: ", BitConverter.ToString(uinttoByte(key128)));
            AddStep("Anahtar: ", toBinaryString(uinttoByte(key128)));

            Encrypt(key128, text64, text64);
            
            // Şifreli metni ekrana yazdırın
            AddStep("Şifreli metin: ", BitConverter.ToString(uinttoByte(text64)));
            AddStep("Şifreli metin: ", toBinaryString(uinttoByte(text64)));
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


        // Encrypt a 64-bit plaintext with a 128-bit key
        public void Encrypt(uint[] masterKey, uint[] plaintext, uint[] ciphertext)
        {
            const int NUM_ROUNDS = 44;

            uint[] keys = new uint[4]
            {
                masterKey[0],
                masterKey[1],
                masterKey[2],
                masterKey[3]
            };
            ciphertext[0] = plaintext[0];
            ciphertext[1] = plaintext[1];

            ciphertext[2] = plaintext[2];
            ciphertext[3] = plaintext[3];

            uint temp;

            uint constant = 0xFFFFFFFC;
            ulong sequence = 0x938BCA3083F;

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

                
                AddStep("Encryption Round : (" + i.ToString() + ") ", toBinaryString(uinttoByte(ciphertext)));
                
            }

            

        }

    }
}
