using System;
using System.Security.Cryptography;

/*Algoritma tamamlanmıştır*/

namespace Algorithms
{
    public class Present 
    {


       public void Initial(string input)
        {

            // Present algoritmasına ait nesne başlatılıyor...
            Algorithms.Present present = new Algorithms.Present();

            // Anahtar 32 byte
             byte[] key = new byte[32] { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };

            // Şifrelenecek Data
            byte[] plaintext = System.Text.Encoding.ASCII.GetBytes("Merhaba Dunya");
            Console.WriteLine("Girilen Metin: " + BitConverter.ToString(plaintext));
            byte[] ciphertext = present.Encrypt(plaintext, key);

            // Print the results
            
            Console.WriteLine("Şifrelenmiş Metin: " + BitConverter.ToString(ciphertext));
          
        }
private readonly byte[] SBox = {
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

    public byte[] Key { get; set; } = Array.Empty<byte>();

    

    private uint[] GenerateRoundKeys(byte[] key)
    {

        if (key.Length != 32)
    {
        throw new ArgumentException("Key 32 bytes olamalı !");
    }
        // Expand the key
        uint[] roundKeys = new uint[32];
        uint[] keyWords = new uint[8];
        for (int i = 0; i < 8; i++)
        {
            keyWords[i] = BitConverter.ToUInt32(key, i * 4);
        }

        // Generate the round keys
        for (int i = 0; i < 32; i++)
        {
            roundKeys[i] = keyWords[7] >> 31;
            for (int j = 6; j >= 0; j--)
            {
                keyWords[j + 1] = (keyWords[j + 1] << 1) | (keyWords[j] >> 31);
            }
           keyWords[0] = (keyWords[0] << 1);
            if (roundKeys[i] == 1)
            {
                keyWords[0] = keyWords[0] ^ 0xC5_06_48_2D;
            }
        }

        return roundKeys;
    }

public byte[] Encrypt(byte[] data, byte[] key)
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
        for (int j = 0; j < 31; j++)
        {
            block = Substitution(block);
            block = Permutation(block);
            block = block ^ roundKeys[j];
        }
        block = Substitution(block);
        block = block ^ roundKeys[31];
        Array.Copy(BitConverter.GetBytes(block), 0, result, i, 8);
    }

    Console.WriteLine("Substitution sonucu: " + Substitution(result[result.Length - 8]));
    Console.WriteLine("Permutation sonucu: " + Permutation(result[result.Length - 8]));

    return result;
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



    }


    }
    
