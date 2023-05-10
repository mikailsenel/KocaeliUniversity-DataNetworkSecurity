


using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
<<<<<<< HEAD
using System.Text;
=======
using Algorithms.Common.DataTransferObjects;
using System;
using System.Reflection.Metadata;
using Algorithms.Common.Abstract;
>>>>>>> 538c252effd4caed75e69343b417da63bf31744c
/*Algoritma tamamlanmıştır.*/
namespace Algorithms;

public class Mysterion : EncryptionAlgorithm
{

    private static uint[]? _key;
    private static uint[]? _state;

<<<<<<< HEAD
        public void Initial(string input)
        {
        byte[] data = System.Text.Encoding.UTF8.GetBytes("hello world");
        Console.WriteLine("Şifrelenecek girdi texti :"+BitConverter.ToString(data));
         Console.WriteLine("Şifrelenecek girdi texti binary gösterimi: " + GetBinaryString(data));
        byte[] key = new byte[] { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };

        byte[] encrypted = Mysterion.Encrypt(data, key);
        Console.WriteLine("Şifrelenmiş data: " + BitConverter.ToString(encrypted));
        Console.WriteLine("Şifrelenmiş data binary gösterimi: " + GetBinaryString(encrypted));

    byte[] decrypted = Mysterion.Decrypt(encrypted, key);
        Console.WriteLine("Şifresi çözülmüş data: " + BitConverter.ToString(decrypted));
        Console.WriteLine("Şifresi çözülmüş data binary gösterimi: " + GetBinaryString(decrypted));
        
        }
 
    public static byte[] Encrypt(byte[] data, byte[] key)
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
public static string GetBinaryString(byte[] data)
{
    StringBuilder binaryString = new StringBuilder();
    foreach (byte b in data)
    {
        string binary = Convert.ToString(b, 2).PadLeft(8, '0');
        binaryString.Append(binary);
    }
    return binaryString.ToString();
}
    private static void Initialize(byte[] key)
=======
    public Mysterion(string text) : base(text)
    {
    }

    protected override void Initial(string input)
    {
        byte[] data = System.Text.Encoding.UTF8.GetBytes(input);
        AddStep( "Şifrelenecek girdi texti", BitConverter.ToString(data));
        Console.WriteLine("Şifrelenecek girdi texti :" + BitConverter.ToString(data));
        byte[] key = new byte[] { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };

        byte[] encrypted = Encrypt(data, key);
        AddStep( "Encrypted", BitConverter.ToString(encrypted));
        Console.WriteLine("Encrypted: " + BitConverter.ToString(encrypted));

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
>>>>>>> 538c252effd4caed75e69343b417da63bf31744c
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

    private  uint[] GetBlock(byte[] data, int blockIndex)
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
<<<<<<< HEAD
        
=======
        AddStep($"Get Blok içeriği {blockIndex}", $" {BitConverter.ToString(BitConverter.GetBytes(block[0]))}-{BitConverter.ToString(BitConverter.GetBytes(block[1]))}");
>>>>>>> 538c252effd4caed75e69343b417da63bf31744c
        Console.WriteLine($"Get Blok içeriği {blockIndex}: {BitConverter.ToString(BitConverter.GetBytes(block[0]))}-{BitConverter.ToString(BitConverter.GetBytes(block[1]))}");
        
        return block;
    }

    private  void EncryptBlock(uint[] block)
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
    }
    private static void Mix()
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
<<<<<<< HEAD
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
public static byte[] Decrypt(byte[] encrypted, byte[] key)
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

private static void DecryptBlock(uint[] block)
{
    uint sum = 0xC6EF3720;
    for (int i = 0; i < 32; i++)
    {
        Mix();
        block[1] -= ((block[0] << 4) + _key[2]) ^ (block[0] + sum) ^ ((block[0] >> 5) + _key[3]);
        block[0] -= ((block[1] << 4) + _key[0]) ^ (block[1] + sum) ^ ((block[1] >> 5) + _key[1]);
        sum -= 0x9E3779B9;
    }
    Console.WriteLine($"Çözülen Blok: {BitConverter.ToString(BitConverter.GetBytes(block[0]))}-{BitConverter.ToString(BitConverter.GetBytes(block[1]))}");
}


}

=======
>>>>>>> 538c252effd4caed75e69343b417da63bf31744c
}




