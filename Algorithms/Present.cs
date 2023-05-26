using Algorithms.Common.Abstract;
using Algorithms.Common.DataTransferObjects;
using Algorithms.Common.Enums;
using System;
using System.Security.Cryptography;
using System.Text;
using static System.Runtime.InteropServices.JavaScript.JSType;
/*Algoritma sağıklı çalışmaktadır.Algoritma tamamlanmıştır.16 byte  128 bit key alır */

namespace Algorithms;

public class Present : EncryptionAlgorithm
{
    public Present(InputDto inputDto) : base(inputDto)
    {

    }

    protected override void Initial(string inputKey, DataTypes inputTypes, DataTypes outputTypes)
    {
         const int MaxInputLength = 16; // 16 byte = 128 bit
       // Anahtar 16 byte
            byte[] key = new byte[16] {
                0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
                0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0
            };
       
        byte[] plaintext = Encoding.ASCII.GetBytes(StringValue);
        // 128 bit üzerinde veri girişi kontrolü
       /* if (plaintext.Length > MaxInputLength)
        {
            Console.WriteLine("Hata: Giriş metni 128 bit (16 byte) üzerinde olamaz.");
            AddStep("Hata: Giriş metni 128 bit (16 byte) üzerinde olamaz.", BitConverter.ToString(plaintext));
            return;
        }*/
        Console.WriteLine("Girilen Metin: " + BitConverter.ToString(plaintext));
            AddStep("Girilen Metin: " , BitConverter.ToString(plaintext));
            Console.WriteLine("Girilen Metin Binary Gösterimi: " + GetBinaryString(plaintext));
            AddStep("Girilen Metin Binary Gösterimi: " , GetBinaryString(plaintext));
            byte[] ciphertext = Encrypt(plaintext, key);
            Console.WriteLine("Şifrelenmiş Metin: " + BitConverter.ToString(ciphertext));
            AddStep("Şifrelenmiş Metin: " , BitConverter.ToString(ciphertext));
            Console.WriteLine("Şifrelenmiş Metin Binary Gösterimi: " + GetBinaryString(ciphertext));
        AddStep("Şifrelenmiş Metin Binary Gösterimi: " , GetBinaryString(ciphertext));
            byte[] decryptedData = Decrypt(ciphertext, key);
            Console.WriteLine("Decrypted Metin: " + BitConverter.ToString(decryptedData));
            AddStep("Decrypted Metin: " , BitConverter.ToString(decryptedData));
            Console.WriteLine("Decrypted Metin Binary Gösterimi: " + GetBinaryString(decryptedData));
       AddStep("Decrypted Metin Binary Gösterimi: " , GetBinaryString(decryptedData));

    }
   private  readonly byte[] SBox = {
            0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
            0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2
        };
    private readonly byte[] PBox = {
    0, 16, 32, 48, 1, 17, 33, 49,
    2, 18, 34, 50, 3, 19, 35, 51,
    4, 20, 36, 52, 5, 21, 37, 53,
    6, 22, 38, 54, 7, 23, 39, 55,
    8, 24, 40, 56, 9, 25, 41, 57,
    10, 26, 42, 58, 11, 27, 43, 59,
    12, 28, 44, 60, 13, 29, 45, 61,
    14, 30, 46, 62, 15, 31, 47, 63
};
public  string GetBinaryString(byte[] data)
        {
            StringBuilder binaryString = new StringBuilder();
            foreach (byte b in data)
            {
                string binary = Convert.ToString(b, 2).PadLeft(8, '0');
                binaryString.Append(binary);
            }
            return binaryString.ToString();
        }
    public byte[] Key { get; set; } = Array.Empty<byte>();



    public  byte[] Encrypt(byte[] data, byte[] key)
        {
            uint[] roundKeys = GenerateRoundKeys(key);
            int length = data.Length;
            int padding = length % 8 == 0 ? 0 : 8 - length % 8;
            length += padding;
            byte[] paddedData = new byte[length];
            Array.Copy(data, paddedData, data.Length);
            for (int i = data.Length; i < length; i++)
            {
                paddedData[i] = (byte)padding;
            }

            byte[] result = new byte[length];
            for (int i = 0; i < length; i += 8)
            {
                ulong block = BitConverter.ToUInt64(paddedData, i);
                block = ConvertEndian(block);

                for (int j = 0; j < 31; j++)
                {
                    block ^= roundKeys[j];
                    block = Substitution(block);
                    block = Permutation(block);
                }
                block ^= roundKeys[31];

                Array.Copy(BitConverter.GetBytes(block), 0, result, i, 8);
            }

            return result;
        }

        public  byte[] Decrypt(byte[] data, byte[] key)
        {
            uint[] roundKeys = GenerateRoundKeys(key);
            int length = data.Length;
            byte[] result = new byte[length];
            for (int i = 0; i < length; i += 8)
            {
                ulong block = BitConverter.ToUInt64(data, i);

                for (int j = 31; j > 0; j--)
                {
                    block ^= roundKeys[j];
                    block = PermutationInverse(block);
                    block = SubstitutionInverse(block);
                }
                block ^= roundKeys[0];

                block = ConvertEndian(block);
                Array.Copy(BitConverter.GetBytes(block), 0, result, i, 8);
            }

            int padding = result[length - 1];
            if (padding > 0 && padding < 9)
            {
                bool validPadding = true;
                for (int i = length - padding; i < length; i++)
                {
                    if (result[i] != padding)
                    {
                        validPadding = false;
                        break;
                    }
                }

                if (validPadding)
                {
                    byte[] unpaddedResult = new byte[length - padding];
                    Array.Copy(result, unpaddedResult, length - padding);
                    result = unpaddedResult;
                }
            }

            return result;
        }
        private  uint[] GenerateRoundKeys(byte[] key)
        {
            if (key.Length != 16)
            {
                throw new ArgumentException("Key must be 16 bytes long!");
            }

            uint[] roundKeys = new uint[32];
            uint[] keyWords = new uint[4];
            for (int i = 0; i < 4; i++)
            {
                keyWords[i] = BitConverter.ToUInt32(key, i * 4);
            }

            for (int i = 0; i < 32; i++)
            {
                roundKeys[i] = keyWords[3] >> 31;
                for (int j = 2; j >= 0; j--)
                {
                    keyWords[j + 1] = (keyWords[j + 1] << 1) | (keyWords[j] >> 31);
                }
                keyWords[0] = (keyWords[0] << 1);
                if (roundKeys[i] == 1)
                {
                    keyWords[0] ^= 0xC5_06_48_2D;
                }
            }

            return roundKeys;
        }

private  ulong ConvertEndian(ulong value)
{
    return ((value & 0xFF) << 56) |
           ((value & 0xFF00) << 40) |
           ((value & 0xFF0000) << 24) |
           ((value & 0xFF000000) << 8) |
           ((value & 0xFF00000000) >> 8) |
           ((value & 0xFF0000000000) >> 24) |
           ((value & 0xFF000000000000) >> 40) |
           ((value & 0xFF00000000000000) >> 56);
}


        private ulong Substitution(ulong block)
        {
            ulong result = 0;
            for (int i = 0; i < 64; i += 4)
            {
                byte nibble = (byte)((block >> i) & 0xF);
                nibble = SBox[nibble];
                result |= (ulong)nibble << i;
            }
            return result;
        }

        private  ulong SubstitutionInverse(ulong block)
        {
            ulong result = 0;
            for (int i = 0; i < 64; i += 4)
            {
                byte nibble = (byte)((block >> i) & 0xF);
                nibble = (byte)Array.IndexOf(SBox, nibble);
                result |= (ulong)nibble << i;
            }
            return result;
        }

        private ulong Permutation(ulong block)
        {
            ulong result = 0;
            for (int i = 0; i < 64; i++)
            {
                ulong bit = (block >> i) & 1;
                result |= bit << PBox[i];
            }
            return result;
        }

        private  ulong PermutationInverse(ulong block)
        {
            ulong result = 0;
            for (int i = 0; i < 64; i++)
            {
                ulong bit = (block >> PBox[i]) & 1;
                result |= bit << i;
            }
            return result;
        }



}




