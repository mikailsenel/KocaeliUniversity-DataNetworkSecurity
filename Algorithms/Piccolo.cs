using Algorithms.Common.Abstract;
using Algorithms.Common.DataTransferObjects;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Text;
using static System.Runtime.InteropServices.JavaScript.JSType;
//Decyrption metodu yanlış çalışıyor
namespace Algorithms
{
    public class Piccolo : EncryptionAlgorithm
    {
        public Piccolo(string text) : base(text)
        {

        }
        public void SetKey(byte[] key)
        {
            if (key.Length != KeySize / 8)
            {
                throw new ArgumentException($"Key size must be {KeySize} bits.");
            }

            subkeys = GenerateSubkeys(key);
        }

        /*public  string GetBinaryString(byte[] data)
        {
            StringBuilder binaryString = new StringBuilder();
            foreach (byte b in data)
            {
                string binary = Convert.ToString(b, 2).PadLeft(8, '0');
                binaryString.Append(binary);
            }
            return binaryString.ToString();
        }*/

        private const int BlockSize = 128;
        private const int KeySize = 128;
        private const int Rounds = 32;

        private ulong[] subkeys;
       private ulong[] GenerateSubkeys(byte[] key)
        {
            ulong[] subkeys = new ulong[Rounds];
            ulong keyBits = BitConverter.ToUInt64(key, 0);

            for (int i = 0; i < Rounds; i++)
            {
                subkeys[i] = keyBits;
                keyBits = RotateLeft(keyBits, 61) ^ keyBits >> 3;
            }

            return subkeys;
        }

    private ulong RotateLeft(ulong value, int count)
    {
        return (value << count) | (value >> (64 - count));
    }

    private ulong RotateRight(ulong value, int count)
    {
        return (value >> count) | (value << (64 - count));
    }

    public byte[] Encrypt(string plaintext)
    {
        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        return Encrypt(plaintextBytes);
    }

    public string DecryptToString(byte[] ciphertext)
    {
        byte[] decryptedBytes = Decrypt(ciphertext);
        return Encoding.UTF8.GetString(decryptedBytes);
    }

    private byte[] Encrypt(byte[] plaintext)
    {
        if (plaintext.Length % (BlockSize / 8) != 0)
        {
            throw new ArgumentException($"Plaintext size must be a multiple of {BlockSize} bits.");
        }

        byte[] ciphertext = new byte[plaintext.Length];
        ulong[] block = new ulong[2];

        for (int i = 0; i < plaintext.Length; i += BlockSize / 8)
        {
            block[0] = BitConverter.ToUInt64(plaintext, i);
            block[1] = BitConverter.ToUInt64(plaintext, i + 8);

            for (int round = 0; round < Rounds; round++)
            {
                block[0] += subkeys[round];
                block[0] = RotateLeft(block[0], (int)(block[1] % (BlockSize - 7)) + 1);
                block[0] ^= block[1];
                block[1] = RotateRight(block[1], (int)(block[0] % (BlockSize - 7)) + 1);
                block[1] ^= block[0];
            }

            Array.Copy(BitConverter.GetBytes(block[0]), 0, ciphertext, i, 8);
            Array.Copy(BitConverter.GetBytes(block[1]), 0, ciphertext, i + 8, 8);
        }

        return ciphertext;
    }

    private byte[] Decrypt(byte[] ciphertext)
    {
        if (ciphertext.Length % (BlockSize / 8) != 0)
        {
            throw new ArgumentException($"Ciphertext size must be a multiple of {BlockSize} bits.");
        }

        byte[] plaintext = new byte[ciphertext.Length];
        ulong[] block = new ulong[2];

        for (int i = 0; i < ciphertext.Length; i += BlockSize / 8)
        {
            block[0] = BitConverter.ToUInt64(ciphertext, i);
            block[1] = BitConverter.ToUInt64(ciphertext, i + 8);

            for (int round = Rounds - 1; round >= 0; round--)
            {
                block[1] ^= block[0];
                block[1] = RotateLeft(block[1], (int)(block[0] % (BlockSize - 7)) + 1);
                block[0] ^= block[1];
                block[0] = RotateRight(block[0], (int)(block[1] % (BlockSize - 7)) + 1);
                block[0] -= subkeys[round];
            }

            Array.Copy(BitConverter.GetBytes(block[0]), 0, plaintext, i, 8);
            Array.Copy(BitConverter.GetBytes(block[1]), 0, plaintext, i + 8, 8);
        }

        return plaintext;
    }
        protected override void Initial(string input,string inputKey)
        {
            /*const int MaxInputLength = 16; // 16 byte = 128 bit
            byte[] key = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
        byte[] plaintext = new byte[] { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
            // 128 bit üzerinde veri girişi kontrolü
            if (plaintext.Length > MaxInputLength)
            {
                Console.WriteLine("Hata: Giriş metni 128 bit (16 byte) üzerinde olamaz.");
                AddStep("Hata: Giriş metni 128 bit (16 byte) üzerinde olamaz.", BitConverter.ToString(plaintext));
                return;
            }

            Console.WriteLine("Şifrelenecek Metin: " + BitConverter.ToString(plaintext).Replace("-", ""));
    AddStep("Şifrelenecek Metin: " , BitConverter.ToString(plaintext).Replace("-", ""));
    Console.WriteLine("Şifrelenecek Metin binary gösterimi: " + GetBinaryString(plaintext));
    AddStep("Şifrelenecek Metin binary gösterimi: " , GetBinaryString(plaintext));
    byte[] ciphertext = Encrypt(key, plaintext);
    AddStep("Şifrelenmiş Metin: " , BitConverter.ToString(ciphertext).Replace("-", ""));
    Console.WriteLine("Şifrelenmiş Metin: " + BitConverter.ToString(ciphertext).Replace("-", ""));
    AddStep("Şifrelenmiş Metin binary gösterimi: " , GetBinaryString(ciphertext));
    Console.WriteLine("Şifrelenmiş Metin binary gösterimi: " + GetBinaryString(ciphertext));

    byte[] decryptedText =Decrypt(key, ciphertext);
    Console.WriteLine("Çözülmüş Metin: " + BitConverter.ToString(decryptedText).Replace("-", ""));
    AddStep("Çözülmüş Metin: " , BitConverter.ToString(decryptedText).Replace("-", ""));
    Console.WriteLine("Çözülmüş Metin binary gösterimi: " + GetBinaryString(decryptedText));
     AddStep("Çözülmüş Metin binary gösterimi: " , GetBinaryString(decryptedText));*/


            const int MaxInputLength = 16; // 16 byte = 128 bit
            byte[] key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

            string plaintext = "Hello, Piccolo Cipher!";


            int requiredLength = (BlockSize / 8) * (int)Math.Ceiling((double)plaintext.Length / (BlockSize / 8));
            plaintext = plaintext.PadRight(requiredLength, '\0');

            /*byte[] data = System.Text.Encoding.UTF8.GetBytes(plaintext);
            // 128 bit üzerinde veri girişi kontrolü
            if (data.Length > MaxInputLength)
            {
                Console.WriteLine("Hata: Giriş metni 128 bit (16 byte) üzerinde olamaz.");
                AddStep("Hata: Giriş metni 128 bit (16 byte) üzerinde olamaz.", BitConverter.ToString(data));
                return;
            }*/
            SetKey(key);
            byte[] ciphertext = Encrypt(plaintext);
            string decryptedText = DecryptToString(ciphertext);

            Console.WriteLine("Plaintext:  " + plaintext);
            AddStep("Plaintext:  " , plaintext);
            Console.WriteLine("Ciphertext: " + BitConverter.ToString(ciphertext).Replace("-", " "));
            AddStep("Ciphertext: " , BitConverter.ToString(ciphertext).Replace("-", " "));
            Console.WriteLine("Decrypted:  " + decryptedText);
            AddStep("Decrypted:  " , decryptedText);

        }

          

    }
}