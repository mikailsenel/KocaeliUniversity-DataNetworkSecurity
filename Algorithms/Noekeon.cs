using Algorithms.Common.Abstract;
using Algorithms.Common.DataTransferObjects;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using static System.Runtime.InteropServices.JavaScript.JSType;


namespace Algorithms;


/*Algoritma tamamlanmıştır. Sağlıklı çalışmaktadır*/


public class Noekeon : EncryptionAlgorithm
{
    public Noekeon(string text) : base(text)
    {
    }
    public string GetByteArrayAsBinaryString(byte[] byteArray)
    {
        string binaryString = "";

        foreach (byte b in byteArray)
        {
            string byteBits = Convert.ToString(b, 2).PadLeft(8, '0');
            binaryString += byteBits;
        }

        return binaryString;
    }
    protected override void Initial(string input)
    {
        /* const int MaxInputLength = 16; // 16 byte = 128 bit
         // Ornek input data
         byte[] inputData = new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, }; //16 bit input data giriş yapılıyor
         // 128 bit üzerinde veri girişi kontrolü
         if (inputData.Length > MaxInputLength)
         {
             Console.WriteLine("Hata: Giriş metni 128 bit (16 byte) üzerinde olamaz.");
             AddStep("Hata: Giriş metni 128 bit (16 byte) üzerinde olamaz.", BitConverter.ToString(inputData));
             return;
         }
         AddStep("Girdi Metin datasi..: " , BitConverter.ToString(inputData));
         Console.WriteLine("Girdi Metin datasi..: " + BitConverter.ToString(inputData));
         AddStep("Girdi Binary datası Binary: " ,GetByteArrayAsBinaryString(inputData));
          Console.WriteLine("Girdi Binary datası Binary: " + GetByteArrayAsBinaryString(inputData));
         // Ornek key
         uint[] key = new uint[] { 0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210 }; //128 bit data

         // Yerine Koyma Islemi
         byte[] outputData = Substitution(inputData);
          AddStep("Yerine koyma islemi sonrasi data..: " , BitConverter.ToString(outputData));
         Console.WriteLine("Yerine koyma islemi sonrasi data..: " + BitConverter.ToString(outputData));
           AddStep("Yerine koyma islemi sonrasi data Binary: " , GetByteArrayAsBinaryString(outputData));
          Console.WriteLine("Yerine koyma islemi sonrasi data Binary: " + GetByteArrayAsBinaryString(outputData));
         // Permutasyon işlemi
         uint a = BitConverter.ToUInt32(outputData, 0);
         uint b = BitConverter.ToUInt32(outputData, 4);
         uint c = BitConverter.ToUInt32(outputData, 8);
         uint d = BitConverter.ToUInt32(outputData, 12);


         Permutation(ref a, ref b, ref c, ref d);
         outputData = BitConverter.GetBytes(a).Concat(BitConverter.GetBytes(b)).Concat(BitConverter.GetBytes(c)).Concat(BitConverter.GetBytes(d)).ToArray();
        AddStep("Permutasyon sonrasi data : " , BitConverter.ToString(outputData));
         Console.WriteLine("Permutasyon sonrasi data : " + BitConverter.ToString(outputData));
         AddStep("Permutasyon sonrasi data Binary: " , GetByteArrayAsBinaryString(outputData));
         Console.WriteLine("Permutasyon sonrasi data Binary: " + GetByteArrayAsBinaryString(outputData));
         //  XOR ve Toplama Islemi
         a = BitConverter.ToUInt32(outputData, 0);
         b = BitConverter.ToUInt32(outputData, 4);
         c = BitConverter.ToUInt32(outputData, 8);
         d = BitConverter.ToUInt32(outputData, 12);

         XOR(ref a, ref b, ref c, ref d, key);
         byte[] xordata = BitConverter.GetBytes(a).Concat(BitConverter.GetBytes(b)).Concat(BitConverter.GetBytes(c)).Concat(BitConverter.GetBytes(d)).ToArray();

        AddStep("Xor sonrasi data: " , BitConverter.ToString(xordata));
         Console.WriteLine("Xor sonrasi data: " + BitConverter.ToString(xordata));
           AddStep("Xor sonrasi data Binary: " , GetByteArrayAsBinaryString(xordata));
         Console.WriteLine("Xor sonrasi data Binary: " + GetByteArrayAsBinaryString(xordata));

         Addition(ref a, ref b, ref c, ref d, key);
         byte[] addition = BitConverter.GetBytes(a).Concat(BitConverter.GetBytes(b)).Concat(BitConverter.GetBytes(c)).Concat(BitConverter.GetBytes(d)).ToArray();
         AddStep("Toplama sonrasi data: " , BitConverter.ToString(addition));
         Console.WriteLine("Toplama sonrasi data: " + BitConverter.ToString(addition));
         AddStep("Toplama sonrasi data Binary: " , GetByteArrayAsBinaryString(addition));
         Console.WriteLine("Toplama sonrasi data Binary: " + GetByteArrayAsBinaryString(addition));
         // Cıktı sonucu

         AddStep(" Sifrelenmiş data..: " , BitConverter.ToString(outputData));
         Console.WriteLine(" Sifrelenmiş data..: " + BitConverter.ToString(outputData));
          AddStep("Sifrelenmiş data Binary: " , GetByteArrayAsBinaryString(outputData));
         Console.WriteLine("Sifrelenmiş data Binary: " + GetByteArrayAsBinaryString(outputData));*/

        string inputText = input;
        string key = "mysecretkey12345";

        Noekeon noekeon = new Noekeon(inputText);
        string encryptedText = noekeon.Encrypt(inputText, key);

        Console.WriteLine("Girdi Metin datasi..: " + inputText);
        AddStep("Girdi Metin datasi..: ", inputText);
        Console.WriteLine("Şifrelenmiş Text: " + encryptedText);
        AddStep("Girdi Metin datasi..: ", encryptedText);


    }

    private const uint Delta = 0x9e3779b9;
    private const int Rounds = 16;
    private uint[] roundKeys;

    public string Encrypt(string input, string key)
    {
        if (key.Length != 16)
        {
            throw new ArgumentException("Key length should be 16 characters.");
        }

        roundKeys = GenerateRoundKeys(key);
        //eklendi
        uint[] block = new uint[4];
        byte[] inputBytes = System.Text.Encoding.UTF8.GetBytes(input);
        int inputLength = inputBytes.Length;
        int outputLength = (inputLength / 16 + 1) * 16;
        byte[] outputBytes = new byte[outputLength];

        for (int i = 0; i < inputLength; i += 16)
        {
            for (int j = 0; j < 16; j++)
            {
                if (i + j < inputLength)
                {
                    block[j / 4] |= (uint)(inputBytes[i + j] << (8 * (j % 4)));
                }
            }

            EncryptBlock(block);

            for (int j = 0; j < 16; j++)
            {
                if (i + j < inputLength)
                {
                    outputBytes[i + j] = (byte)(block[j / 4] >> (8 * (j % 4)));
                }
            }
        }

        return System.Text.Encoding.UTF8.GetString(outputBytes);
    }

    private void EncryptBlock(uint[] block)
    {
        uint x0 = block[0];
        uint x1 = block[1];
        uint x2 = block[2];
        uint x3 = block[3];

        for (int round = 0; round < Rounds; round++)
        {
            uint temp = x3;
            x3 = x2 ^ ((x1 & (x0 ^ x2)) ^ x0 ^ roundKeys[round]);
            x2 = x1;
            x1 = x0;
            x0 = temp;
        }

        block[0] = x0;
        block[1] = x1;
        block[2] = x2;
        block[3] = x3;
    }

    private uint[] GenerateRoundKeys(string key)
    {
        uint[] keyWords = new uint[4];

        for (int i = 0; i < 16; i += 4)
        {
            keyWords[i / 4] = (uint)(key[i] << 24) |
                             (uint)(key[i + 1] << 16) |
                             (uint)(key[i + 2] << 8) |
                             (uint)(key[i + 3]);
        }

        uint[] roundKeys = new uint[Rounds];

        roundKeys[0] = keyWords[0];
        roundKeys[1] = keyWords[1];
        roundKeys[2] = keyWords[2];
        roundKeys[3] = keyWords[3];

        for (int i = 4; i < Rounds; i++)
        {
            roundKeys[i] = roundKeys[i - 4] ^ RotateLeft(roundKeys[i - 1], 3) ^ Delta ^ (uint)i;
        }

        return roundKeys;
    }

    private uint RotateLeft(uint value, int count)
    {
        return (value << count) | (value >> (32 - count));
    }
}




