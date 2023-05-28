using Algorithms.Common.Abstract;
using Algorithms.Common.DataTransferObjects;
using Algorithms.Common.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading.Tasks;
using static System.Runtime.InteropServices.JavaScript.JSType;


namespace Algorithms;


/*Algoritma tamamlanmıştır. Sağlıklı çalışmaktadır. 64 bit key alır ör:4d79536563726574*/


public class Noekeon : EncryptionAlgorithm
{
    public Noekeon(InputDto inputDto) : base(inputDto)
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
    protected override void Initial(string inputKey, DataTypes inputTypes, DataTypes outputTypes)
    {



        /* if (input.Length > MaxInputLength)
         {
             Console.WriteLine("Hata: Giriş metni 128 bit (16 byte) üzerinde olamaz.");
             AddStep("Hata: Giriş metni 128 bit (16 byte) üzerinde olamaz.", input);
             return;
         }*/
        string inputText = StringValue;


        string key = inputKey; //64 bit key alır ör:4d79536563726574
        if (key.Length != 16)
        {
            throw new ArgumentException("Key uzunluğu 64 bit (16 karakter) olmalıdır.");
            return;
        }

        byte[] binaryDatakey = GetBinaryDataFromHexString(key);
        string binaryStringkey = GetBinaryString(binaryDatakey);


        AddStep("Girilen Key..: ", key);

        AddStep("Girilen Key Binary..: ", binaryStringkey);

        string encryptedText = Encrypt(inputText, key);

        Console.WriteLine("Girdi Metin datasi..: " + inputText);
        AddStep("Girdi Metin datasi..: ", inputText);
        byte[] binaryData = GetBinaryDataFromString(inputText);
        string binaryString = GetBinaryString(binaryData);

        AddStep("Girdi Metin datasi Binary data..: ", binaryString);

        Console.WriteLine("Şifrelenmiş Text: " + encryptedText);
        AddStep("Şifrelenmiş Text..: ", encryptedText);

        byte[] binaryDataenc = GetBinaryDataFromString(encryptedText);
        string binaryStringenc = GetBinaryString(binaryDataenc);

        AddStep("Şifrelenmiş Text Binary data..: ", binaryStringenc);

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
    public byte[] GetBinaryDataFromStringenc(string input)
    {
        int length = input.Length;
        byte[] binaryData = new byte[length * 8];

        for (int i = 0; i < length; i++)
        {
            char c = input[i];
            string binary = Convert.ToString(c, 2).PadLeft(8, '0');

            for (int j = 0; j < 8; j++)
            {
                binaryData[i * 8 + j] = (byte)char.GetNumericValue(binary[j]);
            }
        }

        return binaryData;
    }



    private const uint Delta = 0x9e3779b9;
    private const int Rounds = 16;
    private uint[] roundKeys;

    public string Encrypt(string input, string key)
    {
        if (key.Length != 16)
        {
            throw new ArgumentException("Key uzunlugu 16 karakter olmali.");
        }

        roundKeys = GenerateRoundKeys(key);
        //eklendi
        uint[] block = new uint[4];
        int inputLength = input.Length;
        int outputLength = (inputLength / 16 + 1) * 16;
        byte[] outputBytes = new byte[outputLength];

        for (int i = 0; i < inputLength; i += 16)
        {
            for (int j = 0; j < 16; j++)
            {
                if (i + j < inputLength)
                {
                    block[j / 4] |= (uint)(input[i + j] << (8 * (j % 4)));
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

        byte[] trimmedOutputBytes = new byte[inputLength];
        Array.Copy(outputBytes, trimmedOutputBytes, inputLength);

        string encodedOutput = Convert.ToBase64String(trimmedOutputBytes);
        return encodedOutput;
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
