


using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
/*Algoritma tamamlanmıştır.*/
namespace Algorithms
{
    using System;
    public class Mysterion
    {

    private static uint[]? _key;
    private static uint[]? _state;

        public void Initial(string input)
        {
        byte[] data = System.Text.Encoding.UTF8.GetBytes("hello world");
        Console.WriteLine("Şifrelenecek girdi texti :"+BitConverter.ToString(data));
        byte[] key = new byte[] { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };

        byte[] encrypted = Mysterion.Encrypt(data, key);
        Console.WriteLine("Encrypted: " + BitConverter.ToString(encrypted));
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

    private static void Initialize(byte[] key)
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

    private static uint[] GetBlock(byte[] data, int blockIndex)
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
        Console.WriteLine($"Get Blok içeriği {blockIndex}: {BitConverter.ToString(BitConverter.GetBytes(block[0]))}-{BitConverter.ToString(BitConverter.GetBytes(block[1]))}");
        return block;
    }

    private static void EncryptBlock(uint[] block)
    {
        uint sum = 0;
        for (int i = 0; i < 32; i++)
        {
            sum += 0x9E3779B9;
            block[0] += ((block[1] << 4) + _key[0]) ^ (block[1] + sum) ^ ((block[1] >> 5) + _key[1]);
            block[1] += ((block[0] << 4) + _key[2]) ^ (block[0] + sum) ^ ((block[0] >> 5) + _key[3]);
            Mix();
        }
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
}

}




