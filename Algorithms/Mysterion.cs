


using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Algorithms.Common.DataTransferObjects;
using System;
using System.Text;
using System.Reflection.Metadata;
using Algorithms.Common.Abstract;
using Algorithms.Common.Enums;
/*Algoritma tamamlanmıştır. 256 bit key uzunluğu kullanır örnek anahtar:0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF */
namespace Algorithms;

public class Mysterion : EncryptionAlgorithm
{

    private static uint[]? _key;
    private static uint[]? _state;

    public Mysterion(InputDto inputDto) : base(inputDto)
    {

    }
    public string GetStringFromBinary(string binaryString)
    {

        if (binaryString.Length % 8 != 0)
        {
            throw new ArgumentException("Binary string length must be a multiple of 8.");
        }

        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < binaryString.Length; i += 8)
        {
            string binaryByte = binaryString.Substring(i, 8);
            byte value = Convert.ToByte(binaryByte, 2);
            stringBuilder.Append((char)value);
        }

        return stringBuilder.ToString();
    }
    public string GetBinaryString(byte[] data) //binary metodu
    {
        StringBuilder binaryString = new StringBuilder();
        foreach (byte b in data)
        {
            string binary = Convert.ToString(b, 2).PadLeft(8, '0');
            binaryString.Append(binary);
        }
        return binaryString.ToString();
    }
    static byte[] ConvertStringToByteArray(string metin)
    {
        // UTF-8 kodlamasını kullanarak string'i byte dizisine dönüştürme
        byte[] byteDizi = Encoding.UTF8.GetBytes(metin);

        return byteDizi;
    }

    private byte[] ConvertHexToByteArray(string hex)
    {
        int length = hex.Length;
        byte[] byteArray = new byte[length / 2];

        for (int i = 0; i < length; i += 2)
        {
            byteArray[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
        }

        return byteArray;
    }



    protected override void Initial(string inputKey, DataTypes inputTypes, DataTypes outputTypes)
    {

        const int MaxInputLength = 16; // 16 byte = 128 bit,

        /* string[] hexValues = input.Split('-');
         byte[] byteData = new byte[hexValues.Length];

         for (int i = 0; i < hexValues.Length; i++)
         {
             byteData[i] = Convert.ToByte(hexValues[i], 16);
         }



         byte[] data = byteData;   Hexadecimal veri girişi kodu */
        // 128 bit üzerinde veri girişi kontrolü
        /* if (data.Length > MaxInputLength)
         {
             Console.WriteLine("Hata: Giriş metni 128 bit (16 byte) üzerinde olamaz.");
             AddStep("Hata: Giriş metni 128 bit (16 byte) üzerinde olamaz.", BitConverter.ToString(data));
             return;
         }*/

        byte[] data = ByteValue;



        AddStep("Şifrelenecek girdi texti", BitConverter.ToString(data));
        Console.WriteLine("Şifrelenecek girdi texti :" + BitConverter.ToString(data));

        AddStep("Şifrelenecek girdi texti binary gösterimi: ", GetBinaryString(data));

        Console.WriteLine("Şifrelenecek girdi texti binary gösterimi: " + GetBinaryString(data));
        string keyHexString = inputKey;
        // Anahtar uzunluğu 32 byte (256 bit) olmadığında istisna fırlatma örnek anahtar:0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
        if (keyHexString.Length != 64) // Her bir byte 2 hexadecimal karakterle temsil edilir
        {
            throw new ArgumentException("Geçersiz anahtar uzunluğu. Anahtar 256 bit (32 byte) olmalıdır.");
        }
        byte[] key = new byte[] { };
        key = Enumerable.Range(0, keyHexString.Length / 2)
                      .Select(x => Convert.ToByte(keyHexString.Substring(x * 2, 2), 16))
                      .ToArray();
        AddStep("Key: ", inputKey);
        byte[] encrypted = Encrypt(data, key);
        AddStep("Şifrelenmiş data: ", BitConverter.ToString(encrypted));
        Console.WriteLine("Şifrelenmiş data: " + BitConverter.ToString(encrypted));
        AddStep("Şifrelenmiş data binary gösterimi: ", GetBinaryString(encrypted));
        Console.WriteLine("Şifrelenmiş data binary gösterimi: " + GetBinaryString(encrypted));

        byte[] decrypted = Decrypt(encrypted, key);
        AddStep("Şifresi çözülmüş data: ", BitConverter.ToString(decrypted));
        Console.WriteLine("Şifresi çözülmüş data: " + BitConverter.ToString(decrypted));
        AddStep("Şifresi çözülmüş data binary gösterimi: ", GetBinaryString(decrypted));
        Console.WriteLine("Şifresi çözülmüş data binary gösterimi: " + GetBinaryString(decrypted));


    }

    public byte[] Encrypt(byte[] data, byte[] key)
    {
        Initialize(key);
        int blockCount = (data.Length + 7) / 8;
        byte[] encrypted = new byte[blockCount * 8];
        for (int i = 0; i < blockCount; i++)
        {
            uint[] block = GetBlock(data, i);
            EncryptBlock(block);
            byte[] blockBytes = new byte[8];
            Buffer.BlockCopy(block, 0, blockBytes, 0, 8);
            Buffer.BlockCopy(blockBytes, 0, encrypted, i * 8, 8);
        }

        return encrypted;
    }

    private void Initialize(byte[] key)
    {
        _key = new uint[8];
        _state = new uint[8];

        for (int i = 0; i < 8; i++)
        {
            _key[i] = BitConverter.ToUInt32(key, i * 4);
            _state[i] = 0x9E3779B9;
        }

        uint sum = 0;
        for (int i = 0; i < 3; i++)
        {
            for (int j = 0; j < 8; j++)
            {
                _state[j] ^= _key[(j + i) % 8];
            }
            Mix();
            sum += _state[i];
        }
        for (int i = 0; i < 8; i++)
        {
            _state[i] ^= _key[i];
        }
        Mix();
        sum += _state[2];

        for (int i = 0; i < 4; i++)
        {
            Mix();
            sum += _state[i];
        }
        _state[0] ^= sum;

    }

    private uint[] GetBlock(byte[] data, int blockIndex)
    {
        uint[] block = new uint[2];
        for (int i = 0; i < 8; i++)
        {
            int index = blockIndex * 8 + i;
            if (index < data.Length)
            {
                block[i / 4] |= (uint)data[index] << (8 * (i % 4));
            }
        }
        AddStep($"Get Blok içeriği {blockIndex}", $" {BitConverter.ToString(BitConverter.GetBytes(block[0]))}-{BitConverter.ToString(BitConverter.GetBytes(block[1]))}");
        Console.WriteLine($"Get Blok içeriği {blockIndex}: {BitConverter.ToString(BitConverter.GetBytes(block[0]))}-{BitConverter.ToString(BitConverter.GetBytes(block[1]))}");
        string binary0 = GetBinaryString(BitConverter.GetBytes(block[0]));
        string binary1 = GetBinaryString(BitConverter.GetBytes(block[1]));
        Console.WriteLine($"Get Blok içeriği: {binary0}-{binary1}");
        AddStep($"Get Blok içeriği binary :{binary0}-{binary1}", $" {binary0}-{binary1}");
        return block;
    }

    private void EncryptBlock(uint[] block)
    {
        uint sum = 0;
        for (int i = 0; i < 32; i++)
        {
            sum += 0x9E3779B9;
            block[0] += ((block[1] << 4) + _key[0]) ^ (block[1] + sum) ^ ((block[1] >> 5) + _key[1]);
            block[1] += ((block[0] << 4) + _key[2]) ^ (block[0] + sum) ^ ((block[0] >> 5) + _key[3]);
            Mix();
        }
        AddStep($"Şifreleme Bloğu", $"Şifreleme Bloğu: {BitConverter.ToString(BitConverter.GetBytes(block[0]))}-{BitConverter.ToString(BitConverter.GetBytes(block[1]))}");
        Console.WriteLine($"Şifreleme Bloğu: {BitConverter.ToString(BitConverter.GetBytes(block[0]))}-{BitConverter.ToString(BitConverter.GetBytes(block[1]))}");
        string binary0 = GetBinaryString(BitConverter.GetBytes(block[0]));
        string binary1 = GetBinaryString(BitConverter.GetBytes(block[1]));
        Console.WriteLine($"Şifreleme Bloğu içeriği: {binary0}-{binary1}");
        AddStep($"Şifreleme Bloğu içeriği binary :{binary0}-{binary1}", $" {binary0}-{binary1}");
    }

    public byte[] Decrypt(byte[] encrypted, byte[] key)
    {
        Initialize(key);
        int blockCount = encrypted.Length / 8;
        byte[] decrypted = new byte[blockCount * 8];
        for (int i = 0; i < blockCount; i++)
        {
            uint[] block = GetBlock(encrypted, i);
            DecryptBlock(block);
            byte[] blockBytes = new byte[8];
            Buffer.BlockCopy(block, 0, blockBytes, 0, 8);
            Buffer.BlockCopy(blockBytes, 0, decrypted, i * 8, 8);
        }

        return decrypted;
    }

    private void DecryptBlock(uint[] block)
    {
        uint sum = 0xC6EF3720;
        for (int i = 0; i < 32; i++)
        {
            Mix();
            block[1] -= ((block[0] << 4) + _key[2]) ^ (block[0] + sum) ^ ((block[0] >> 5) + _key[3]);
            block[0] -= ((block[1] << 4) + _key[0]) ^ (block[1] + sum) ^ ((block[1] >> 5) + _key[1]);
            sum -= 0x9E3779B9;
        }
        AddStep($"Şifreleme Bloğu", $"Çözülen Blok: {BitConverter.ToString(BitConverter.GetBytes(block[0]))}-{BitConverter.ToString(BitConverter.GetBytes(block[1]))}");
        Console.WriteLine($"Çözülen Blok: {BitConverter.ToString(BitConverter.GetBytes(block[0]))}-{BitConverter.ToString(BitConverter.GetBytes(block[1]))}");
        string binary0 = GetBinaryString(BitConverter.GetBytes(block[0]));
        string binary1 = GetBinaryString(BitConverter.GetBytes(block[1]));
        Console.WriteLine($"Şifreleme Bloğu çözülen içerik binary: {binary0}-{binary1}");
        AddStep($"Şifreleme Bloğu çözülen içerik binary :{binary0}-{binary1}", $" {binary0}-{binary1}");
    }

    private void Mix()
    {
        if (_state == null)
        {
            throw new ArgumentNullException(nameof(_state));
        }
        uint t = _state[0];
        _state[0] = _state[1];
        _state[1] = _state[2];
        _state[2] = _state[3];
        _state[3] = t ^ _state[4] ^ _state[6] ^ (_state[7] << 16);
        _state[4] = _state[5];
        _state[5] = _state[6];
        _state[6] = _state[7];
        _state[7] = _state[7];
        _state[7] = t;
    }

}
