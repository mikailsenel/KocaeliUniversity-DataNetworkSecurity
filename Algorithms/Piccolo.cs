using Algorithms.Common.Abstract;
using Algorithms.Common.DataTransferObjects;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Text;
using static System.Runtime.InteropServices.JavaScript.JSType;
using Algorithms.Common.Enums;
using System.ComponentModel.DataAnnotations;
//Algoritma Sağlıklı Çalışmaktadır.128 bit key alır
namespace Algorithms
{
    public class Piccolo : EncryptionAlgorithm
    {
        public Piccolo(InputDto inputDto) : base(inputDto)
        {

        }
        public void SetKey(byte[] key)
        {
            if (key.Length != KeySize / 8)
            {
                ThrowBusinessException($"Key  {KeySize} olmalı bit.");
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

        public byte[] GetBinaryDataFromHexString(string hexString)
        {
            int length = hexString.Length;
            byte[] binaryData = new byte[length / 2];

            for (int i = 0; i < length; i += 2)
            {
                string hexByte = hexString.Substring(i, 2);
                byte value = Convert.ToByte(hexByte, 16);
                binaryData[i / 2] = value;
            }

            return binaryData;
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
                throw new ArgumentException($"Plaintext uzunluğu  {BlockSize}'ın katı bit uzunluğunda olmalıdır.");
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
                ThrowBusinessException($"Ciphertext uzunluğu  {BlockSize}'ın katı bit uzunluğunda olmalıdır.");
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
        protected override void Initial(string inputKey, DataTypes inputTypes, DataTypes outputTypes)
        {
            const int MaxInputLength = 16; // 16 byte = 128 bit

            string keyHexString = inputKey;
            // Anahtar uzunluğu 16 byte (128 bit) olmadığında istisna fırlatma örnek anahtar:0123456789ABCDEF0123456789ABCDEF
            if (keyHexString.Length != 32) // Her bir byte 2 hexadecimal karakterle temsil edilir
            {
                ThrowBusinessException("Geçersiz anahtar uzunluğu. Anahtar 128 bit (16 byte) olmalıdır.");
            }
            byte[] key = new byte[] { };
            key = Enumerable.Range(0, keyHexString.Length / 2)
                          .Select(x => Convert.ToByte(keyHexString.Substring(x * 2, 2), 16))
                          .ToArray();


            // Giriş metnini UTF-8 olarak byte dizisine dönüştür
            byte[] data = ByteValue;

            // Giriş metnini gereken uzunluğa tamamla
            int requiredLength = (BlockSize / 8) * (int)Math.Ceiling((double)data.Length / (BlockSize / 8));
            byte[] paddedData = new byte[requiredLength];
            Array.Copy(data, paddedData, data.Length);

            // 128 bit üzerinde veri girişi kontrolü
            /* if (data.Length > MaxInputLength)
             {
                 Console.WriteLine("Hata: Giriş metni 128 bit (16 byte) üzerinde olamaz.");
                 AddStep("Hata: Giriş metni 128 bit (16 byte) üzerinde olamaz.", BitConverter.ToString(data));
                 return;
             }*/

            SetKey(key);
            string binaryStringkey = GetBinaryString(key);
            AddStep("Girilen Key..:", BitConverter.ToString(key));
            AddStep("Girilen Key Binary..:", binaryStringkey);
            byte[] ciphertext = Encrypt(paddedData);
            string decryptedText = DecryptToString(ciphertext);

            Console.WriteLine("Girilen Metin..:  " + HexValue);
            AddStep("Girilen Metin..:", HexValue);
            AddStep("Girilen Metin Binary", ConvertToBinary(HexValue));

            Console.WriteLine("Şifreli Metin..: " + BitConverter.ToString(ciphertext).Replace("-", " "));
            AddStep("Şifreli Metin..: ", BitConverter.ToString(ciphertext).Replace("-", " "));
            string binarydec = GetBinaryString(ciphertext);
            AddStep("Şifreli Metin Binary..:", binarydec);
            Console.WriteLine("Deşifrelenmiş Metin..:  " + decryptedText.TrimEnd('\0'));
            AddStep("Deşifrelenmiş Metin..:  ", decryptedText.TrimEnd('\0'));
            FinalStep(decryptedText.TrimEnd('\0'), DataTypes.String, outputTypes);
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