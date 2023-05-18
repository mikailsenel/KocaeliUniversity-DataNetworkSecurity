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
                throw new ArgumentException($"Key  {KeySize} olmalı bit.");
            }

            subkeys = GenerateSubkeys(key);
        }

        public string GetBinaryString(byte[] binaryData)
        {
            StringBuilder binaryString = new StringBuilder();

            foreach (byte b in binaryData)
            {
                string binary = Convert.ToString(b, 2).PadLeft(8, '0');
                binaryString.Append(binary);
            }

            return binaryString.ToString();
        }

        public byte[] GetBinaryDataFromString(string input)
        {
            int length = input.Length;
            byte[] binaryData = new byte[length];

            for (int i = 0; i < length; i++)
            {
                binaryData[i] = Convert.ToByte(input[i]);
            }

            return binaryData;
        }
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

            int requiredLength = (BlockSize / 8) * (int)Math.Ceiling((double)plaintextBytes.Length / (BlockSize / 8));
            byte[] paddedPlaintext = new byte[requiredLength];
            Array.Copy(plaintextBytes, paddedPlaintext, plaintextBytes.Length);

            return Encrypt(paddedPlaintext);
        }


        public string DecryptToString(byte[] ciphertext)
        {
            byte[] decryptedBytes = Decrypt(ciphertext);

            // Boşluk karakterlerini çıkar
            int nullIndex = Array.IndexOf(decryptedBytes, (byte)0);
            if (nullIndex != -1)
                decryptedBytes = decryptedBytes.Take(nullIndex).ToArray();

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
        protected override void Initial(string input, string inputKey)
        {
            const int MaxInputLength = 16; // 16 byte = 128 bit
            byte[] key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

            // Giriş metnini UTF-8 olarak byte dizisine dönüştür
            byte[] data = Encoding.UTF8.GetBytes(input);

            // Giriş metnini gereken uzunluğa tamamla
            int requiredLength = (BlockSize / 8) * (int)Math.Ceiling((double)data.Length / (BlockSize / 8));
            byte[] paddedData = new byte[requiredLength];
            Array.Copy(data, paddedData, data.Length);

            // 128 bit üzerinde veri girişi kontrolü
            if (data.Length > MaxInputLength)
            {
                Console.WriteLine("Hata: Giriş metni 128 bit (16 byte) üzerinde olamaz.");
                AddStep("Hata: Giriş metni 128 bit (16 byte) üzerinde olamaz.", BitConverter.ToString(data));
                return;
            }

            SetKey(key);
            string binaryStringkey = GetBinaryString(key);
            AddStep("Girilen Key..:", BitConverter.ToString(key));
            AddStep("Girilen Key Binary..:", binaryStringkey);
            byte[] ciphertext = Encrypt(paddedData);
            string decryptedText = DecryptToString(ciphertext);

            Console.WriteLine("Girilen Metin..:  " + input);
            AddStep("Girilen Metin..:", input);
            AddStep("Girilen Metin Binary", ConvertToBinary(input));

            Console.WriteLine("Şifreli Metin..: " + BitConverter.ToString(ciphertext).Replace("-", " "));
            AddStep("Şifreli Metin..: ", BitConverter.ToString(ciphertext).Replace("-", " "));

            string binarydec = GetBinaryString(ciphertext);
            AddStep("Şifreli Metin Binary..:", binarydec);

            Console.WriteLine("Deşifrelenmiş Metin..:  " + decryptedText.TrimEnd('\0'));
            AddStep("Deşifrelenmiş Metin..:  ", decryptedText.TrimEnd('\0'));

            AddStep("Deşifrelenmiş Metin Binary...:", ConvertToBinary(decryptedText.TrimEnd('\0')));
        }

        static string ConvertToBinary(string data)
        {
            byte[] binaryData = Encoding.Default.GetBytes(data);
            StringBuilder binaryStringBuilder = new StringBuilder();

            foreach (byte b in binaryData)
            {
                binaryStringBuilder.Append(Convert.ToString(b, 2).PadLeft(8, '0'));
            }

            return binaryStringBuilder.ToString();
        }


    }
}