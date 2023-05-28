using System;
using Algorithms.Common.Abstract;
using System.Text;
using Algorithms.Common.DataTransferObjects;
using Algorithms.Common.Enums;

public class RC512: EncryptionAlgorithm
{
    private const int WordSize = 32;
    private const int NumRounds = 12;
    private const int KeySize = 16; // In bytes

    private uint[] _roundKey = null;

    public RC512(InputDto inputDto) : base(inputDto)
    {

    }

    protected override void Initial(string inputKey, DataTypes inputTypes, DataTypes outputTypes)
    {
        if (inputKey.Length != 16) {
            throw new ArgumentException("Key uzunluğu (16 byte, 128 bit) olmalı.");
        }
        byte[] key = Encoding.ASCII.GetBytes(inputKey);
        InitializeKey(Encoding.ASCII.GetBytes(inputKey));

        // ----------------------------------------------------------------

        Console.WriteLine($"Plaintext: '{StringValue}'");
        AddStep("Plaintext", StringValue);

        byte[] strencrypted = this.EncryptString(key, StringValue);
        AddStep("Şifrelenmiş Metin", BitConverter.ToString(strencrypted));
        Console.WriteLine("Şifrelenmiş Metin: " + BitConverter.ToString(strencrypted));

        string strdecrypted = this.DecryptString(key, strencrypted);
        AddStep("Deşifrelenmiş Metin: ", strdecrypted);
        Console.WriteLine($"Decrypted: '{strdecrypted}'");

        // ----------------------------------------------------------------
        // byte[] data = new byte[]{
        //     0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
        //     0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0
        // };

        // // RC512 rc5 = new RC512("asdfasdfasdfasdf");
        // AddStep("Şifrelenecek Metin binary gösterimi: ", BitConverter.ToString(data));

        // byte[] encryptedData = Encrypt(data);
        // AddStep("Şifrelenecek Metin binary gösterimi: ", BitConverter.ToString(encryptedData));

        // byte[] decryptedData = Decrypt(encryptedData);
        // AddStep("Şifrelenecek Metin binary gösterimi: ", BitConverter.ToString(decryptedData));

        // Console.WriteLine("Data:           " + BitConverter.ToString(data));
        // Console.WriteLine("Encrypted Data: " + BitConverter.ToString(encryptedData));
        // Console.WriteLine("Decrypted Data: " + BitConverter.ToString(decryptedData));
        // ----------------------------------------------------------------
    }

    private void InitializeKey(byte[] key)
    {
        int numWords = KeySize / sizeof(uint);
        uint[] keyWords = new uint[numWords];

        for (int ii = 0; ii < numWords; ii++)
        {
            keyWords[ii] = BitConverter.ToUInt32(key, ii * sizeof(uint));
        }

        _roundKey = new uint[2 * (NumRounds + 1)];
        _roundKey[0] = 0xB7E15163;

        for (int ii = 1; ii < _roundKey.Length; ii++)
        {
            _roundKey[ii] = _roundKey[ii - 1] + 0x9E3779B9;
        }

        int maxKeyWords = Math.Max(numWords, _roundKey.Length);

        uint i = 0;
        uint j = 0;
        uint a = 0;
        uint b = 0;

        for (int k = 0; k < 3 * maxKeyWords; k++)
        {
            a = _roundKey[i] = RotateLeft(_roundKey[i] + a + b, 3);
            b = keyWords[j] = RotateLeft(keyWords[j] + a + b, (int)(a + b));
            i = (i + 1) % (uint)_roundKey.Length;
            j = (j + 1) % (uint)numWords;
        }
    }

    private uint RotateLeft(uint value, int shift)
    {
        shift &= 0x1F;
        return (value << shift) | (value >> (WordSize - shift));
    }

    private uint RotateRight(uint value, int shift)
    {
        shift &= 0x1F;
        return (value >> shift) | (value << (WordSize - shift));
    }

    public byte[] uintArrayToBytes(uint[] uintArray)
    {
        byte[] byteArray = new byte[uintArray.Length * 4];
        Buffer.BlockCopy(uintArray, 0, byteArray, 0, uintArray.Length * 4);
        return byteArray;
    }

    public byte[] Encrypt(byte[] input)
    {
        if (input == null)
        {
            throw new ArgumentNullException(nameof(input));
        }

        if (input.Length % sizeof(uint) != 0)
        {
            throw new ArgumentException("Invalid input size. Input size must be a multiple of 4 bytes.");
        }

        int numBlocks = input.Length / sizeof(uint);
        uint[] blocks = new uint[numBlocks];

        for (int i = 0; i < numBlocks; i++)
        {
            blocks[i] = BitConverter.ToUInt32(input, i * sizeof(uint));
        }

        for (int i = 0; i < numBlocks; i += 2)
        {
            uint a = blocks[i];
            uint b = blocks[i + 1];

            a += _roundKey[0];
            b += _roundKey[1];

            for (int j = 1; j <= NumRounds; j++)
            {
                a = RotateLeft(a ^ b, (int)b) + _roundKey[2 * j];
                b = RotateLeft(b ^ a, (int)a) + _roundKey[2 * j + 1];
                // AddStep($"Encrypt Afer Blok Rotation", BitConverter.ToString(uintArrayToBytes(blocks)));
            }

            blocks[i] = a;
            blocks[i + 1] = b;
            AddStep($"Encrypt Afer Key Addition", BitConverter.ToString(uintArrayToBytes(blocks)));
        }

        byte[] encryptedData = new byte[numBlocks * sizeof(uint)];

        for (int i = 0; i < numBlocks; i++)
        {
            byte[] blockBytes = BitConverter.GetBytes(blocks[i]);
            Buffer.BlockCopy(blockBytes, 0, encryptedData, i * sizeof(uint), sizeof(uint));
        }

        return encryptedData;
    }

    public byte[] Decrypt(byte[] input)
    {
        if (input == null)
        {
            throw new ArgumentNullException(nameof(input));
        }

        if (input.Length % sizeof(uint) != 0)
        {
            throw new ArgumentException("Invalid input size. Input size must be a multiple of 4 bytes.");
        }

        int numBlocks = input.Length / sizeof(uint);
        uint[] blocks = new uint[numBlocks];

        for (int i = 0; i < numBlocks; i++)
        {
            blocks[i] = BitConverter.ToUInt32(input, i * sizeof(uint));
        }

        for (int i = numBlocks - 2; i >= 0; i -= 2)
        {
            uint a = blocks[i];
            uint b = blocks[i + 1];

            for (int j = NumRounds; j > 0; j--)
            {
                b = RotateRight(b - _roundKey[2 * j + 1], (int)a) ^ a;
                a = RotateRight(a - _roundKey[2 * j], (int)b) ^ b;
                // AddStep($"Decrypt Afer Blok Rotation", BitConverter.ToString(uintArrayToBytes(blocks)));
            }

            b -= _roundKey[1];
            a -= _roundKey[0];

            blocks[i] = a;
            blocks[i + 1] = b;

            AddStep($"Decrypt Afer Key Addition", BitConverter.ToString(uintArrayToBytes(blocks)));
        }

        byte[] decryptedData = new byte[numBlocks * sizeof(uint)];

        for (int i = 0; i < numBlocks; i++)
        {
            byte[] blockBytes = BitConverter.GetBytes(blocks[i]);
            Buffer.BlockCopy(blockBytes, 0, decryptedData, i * sizeof(uint), sizeof(uint));
        }

        return decryptedData;
    }

    public byte[] EncryptString(byte[] key, string plaintext)
    {
        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        List<byte> ciphertext = new List<byte>();

        int blockSize = 8;
        int totalBlocks = (int)Math.Ceiling((double)plaintextBytes.Length / blockSize);

        for (int blockIndex = 0; blockIndex < totalBlocks; blockIndex++)
        {
            int startIndex = blockIndex * blockSize;
            int endIndex = Math.Min(startIndex + blockSize, plaintextBytes.Length);
            int blockLength = endIndex - startIndex;

            byte[] block = new byte[blockSize];
            Array.Copy(plaintextBytes, startIndex, block, 0, blockLength);

            byte[] encryptedBlock = Encrypt(block);
            ciphertext.AddRange(encryptedBlock);
            AddStep($"Şifrelenmiş Blok {blockIndex}", BitConverter.ToString(encryptedBlock));
        }

        return ciphertext.ToArray();
    }

    public string DecryptString(byte[] key, byte[] ciphertext)
    {
        List<byte> plaintextBytes = new List<byte>();

        int blockSize = 8;
        int totalBlocks = ciphertext.Length / blockSize;

        for (int blockIndex = 0; blockIndex < totalBlocks; blockIndex++)
        {
            int startIndex = blockIndex * blockSize;
            byte[] block = new byte[blockSize];
            Array.Copy(ciphertext, startIndex, block, 0, blockSize);

            byte[] decryptedBlock = Decrypt(block);
            plaintextBytes.AddRange(decryptedBlock);
            AddStep($"Deşifrelenmiş Blok {blockIndex}", BitConverter.ToString(decryptedBlock));
        }

        return Encoding.ASCII.GetString(plaintextBytes.ToArray()).Trim('\0');
    }
}
