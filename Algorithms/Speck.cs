using Algorithms.Common.Abstract;

namespace Algorithms;

using System;
using System.Text;
using System.Runtime.InteropServices;
using Algorithms.Common.Enums;
using Algorithms.Common.DataTransferObjects;
using System.Diagnostics;
using System.Collections;

public class Speck : EncryptionAlgorithm
{
    public Speck(InputDto inputDto) : base(inputDto)
    {
        
    }

    protected override void Initial(string inputKey, DataTypes inputTypes, DataTypes outputTypes)
    {

        byte[] key = Encoding.ASCII.GetBytes(inputKey);
        byte[] ciphertext;
        byte[] plaintext;

        if (inputKey.Length != 12)
        {
            throw new ArgumentException("Key uzunluğu (12 byte, 96 bit) olmalı.");
        }

        string plaintextR = StringValue;
        Console.WriteLine("Şifrelenecek girdi: " + plaintextR);
        AddStep("Şifrelenecek girdi", plaintextR);

        



        if (inputTypes==DataTypes.Hex)
        {
             plaintext = Enumerable.Range(0, plaintextR.Length)
                                     .Where(x => x % 2 == 0)
                                     .Select(x => Convert.ToByte(plaintextR.Substring(x, 2), 16))
                                     .ToArray();
        }
        else if (inputTypes == DataTypes.String)
        {
            plaintext = Encoding.UTF8.GetBytes(plaintextR);

        }
        else
        {
            
            string[] stringBytes = plaintextR.Split('-');
            plaintext = new byte[stringBytes.Length];

            for (int i = 0; i < stringBytes.Length; i++)
            {
                plaintext[i] = Convert.ToByte(stringBytes[i], 16); // Hexadecimal olarak çevirme
            }
            
        }

        ciphertext = EncryptString(plaintext, key);
        AddStep("Şifrelenmiş girdi", System.Text.Encoding.UTF8.GetString(ciphertext));


        byte[] decryptedtext = DecryptString(ciphertext, key);


        if (outputTypes == DataTypes.Hex)
        {
            
            string DEChex = BitConverter.ToString(decryptedtext).Replace("-", "");
            AddStep("şifresi çözülen mesaj:", DEChex);
            Console.WriteLine("Deşifrelenmiş girdi: " + DEChex);

        }
        else if (outputTypes == DataTypes.String)
        {
            
            string result = System.Text.Encoding.UTF8.GetString(decryptedtext);
            AddStep("şifresi çözülen mesaj:", result);
            Console.WriteLine("Deşifrelenmiş girdi: " + result);
        }
        else
        {

            string result = BitConverter.ToString(decryptedtext);
            AddStep("şifresi çözülen mesaj  :", result);
            Console.WriteLine("Deşifrelenmiş girdi: " + result);

        }


            Console.WriteLine("complated");

    }
    public static int _rounds = 26;//EncryptionType.Speck_64_96   => 26,
    public static uint[] _scheduledKey;

    private static byte[] encript(byte[] payload)
    {

        int blockSize = 8;


        byte[] encrypted = new byte[payload.Length];
        uint[] plainTextBlock = new uint[2];
        uint[] cipherTextBlock = new uint[2];


        for (int i = 0; i < payload.Length; i += blockSize)
        {
            int j = i + (blockSize / 2);
            plainTextBlock[0] = BitConverter.ToUInt32(payload, i);
            plainTextBlock[1] = BitConverter.ToUInt32(payload, j);

            EncryptBlock(plainTextBlock, ref cipherTextBlock);

            byte[] firstHalf = BitConverter.GetBytes(cipherTextBlock[0]);
            byte[] secondHalf = BitConverter.GetBytes(cipherTextBlock[1]);
            Buffer.BlockCopy(firstHalf, 0, encrypted, i, firstHalf.Length);
            Buffer.BlockCopy(secondHalf, 0, encrypted, j, secondHalf.Length);
        }
        return encrypted;
    }

    private static byte[] decript(byte[] cipherText)
    {
        int blockSize = 8;
        byte[] decrypted = new byte[cipherText.Length];

        uint[] plainTextBlock = new uint[2];
        uint[] cipherTextBlock = new uint[2];
        for (int i = 0; i < cipherText.Length; i += blockSize)
        {
            int j = i + (blockSize / 2);
            cipherTextBlock[0] = BitConverter.ToUInt32(cipherText, i);
            cipherTextBlock[1] = BitConverter.ToUInt32(cipherText, j);

            DecryptBlock(cipherTextBlock, ref plainTextBlock);

            byte[] firstHalf = BitConverter.GetBytes(plainTextBlock[0]);
            byte[] secondHalf = BitConverter.GetBytes(plainTextBlock[1]);
            Buffer.BlockCopy(firstHalf, 0, decrypted, i, firstHalf.Length);
            Buffer.BlockCopy(secondHalf, 0, decrypted, j, secondHalf.Length);
        }

        return decrypted;
    }

    private static uint[] KeySchedule(byte[] keyBytes)
    {


        int keyPartSize = sizeof(uint);
        int numberOfKeyParts = keyBytes.Length / keyPartSize;
        uint[] key = new uint[numberOfKeyParts];
        int keyIdx = 0;
        for (int offset = 0; offset < keyPartSize * numberOfKeyParts; offset += keyPartSize)
        {
            key[keyIdx++] = BitConverter.ToUInt32(keyBytes, offset);
        }



        uint rounds = 26;
        uint[] scheduledKey = new uint[rounds];

        uint a = key[0];
        uint b = key[1];
        uint c = key[2];
        for (uint i = 0; i < rounds;)
        {
            scheduledKey[i] = a;
            SpeckEncryptRound(ref b, ref a, i++);
            scheduledKey[i] = a;
            SpeckEncryptRound(ref c, ref a, i++);
        }

        return scheduledKey;


    }



    public static void EncryptBlock(uint[] plainTextBlock, ref uint[] cipherTextBlock)
    {
        Debug.Assert(plainTextBlock.Length == 2);
        Debug.Assert(cipherTextBlock.Length == 2);
        cipherTextBlock[0] = plainTextBlock[0];
        cipherTextBlock[1] = plainTextBlock[1];
        for (int i = 0; i < _rounds; ++i)
        {
            SpeckEncryptRound(ref cipherTextBlock[1], ref cipherTextBlock[0], _scheduledKey[i]);
        }
    }

    public static void DecryptBlock(uint[] cipherTextBlock, ref uint[] plainTextBlock)
    {
        Debug.Assert(plainTextBlock.Length == 2);
        Debug.Assert(cipherTextBlock.Length == 2);
        plainTextBlock[0] = cipherTextBlock[0];
        plainTextBlock[1] = cipherTextBlock[1];
        for (long i = (long)_rounds - 1; i >= 0; --i)
        {
            SpeckDecryptRound(ref plainTextBlock[1], ref plainTextBlock[0], _scheduledKey[i]);
        }
    }

    private static uint RotateRight(uint x, int r)
    {
        return (x >> r) | (x << (32 - r)); ;
    }

    private static uint RotateLeft(uint x, int r)
    {
        return (x << r) | (x >> (32 - r));
    }

    private static void SpeckEncryptRound(ref uint x, ref uint y, uint k)
    {
        x = RotateRight(x, 8);
        x += y;
        x ^= k;
        y = RotateLeft(y, 3);
        y ^= x;
    }

    private static void SpeckDecryptRound(ref uint x, ref uint y, uint k)
    {
        y ^= x;
        y = RotateRight(y, 3);
        x ^= k;
        x -= y;
        x = RotateLeft(x, 8);
    }








    const int READ_RAM_DATA_BYTE = 0;
    const int READ_ROUND_KEY_BYTE = READ_RAM_DATA_BYTE;

    const int BLOCK_SIZE = 8;
    const int KEY_SIZE = 16;
    const int ROUND_KEYS_SIZE = 16;
    const int NUMBER_OF_ROUNDS = 12;

    static byte ROTL(byte x)
    {
        return (byte)(((x) << 1) | ((x) >> 7));
    }

    static void rrr_sbox(ref byte[] data)
    {
        byte temp = data[3];
        data[3] &= data[2];
        data[3] ^= data[1];
        data[1] |= data[2];
        data[1] ^= data[0];
        data[0] &= data[3];
        data[0] ^= temp;
        temp &= data[1];
        data[2] ^= temp;
    }

    void rrr_L(ref byte[] data)
    {
        byte temp = data[0];
        temp = ROTL(temp);
        temp ^= data[0];
        temp = ROTL(temp);
        data[0] ^= temp;
    }

    void rrr_SLK(ref byte[] data, IntPtr key_part)
    {
        byte i;
        rrr_sbox(ref data);
        for (i = 0; i < 4; i++)
        {
            rrr_L(ref data);
            data[i] ^= (byte)Marshal.ReadByte(key_part, i);
        }
    }

    void rrr_enc_dec_round(ref byte[] block, IntPtr roundKey, byte round, ref byte[] key_ctr, byte mode)
    {
        byte i;
        byte[] temp = new byte[4];
        Array.Copy(block, temp, 4);

        rrr_SLK(ref block, roundKey + key_ctr[0]);
        key_ctr[0] = (byte)((key_ctr[0] + 4) & 15);
        rrr_SLK(ref block, roundKey + key_ctr[0]);
        key_ctr[0] = (byte)((key_ctr[0] + 4) & 15);
        block[3] ^= round;
        rrr_SLK(ref block, roundKey + key_ctr[0]);
        if (mode == 1)
            key_ctr[0] = (byte)((key_ctr[0] + 12) & 15);
        else
            key_ctr[0] = (byte)((key_ctr[0] + 4) & 15);
        rrr_sbox(ref block);

        for (i = 0; i < 4; i++)
            block[i] ^= block[i + 4];
        for (i = 0; i < 4; i++)
            block[i + 4] = temp[i];
    }

    public byte[] Encrypt(byte[] block, IntPtr roundKeys)
    {
        byte i;
        byte[] temp = new byte[4] { 0, 0, 0, 0 };
        temp[0] = 4;
        for (i = 0; i < 4; i++)
        {
            block[i] ^= (byte)Marshal.ReadByte(roundKeys, i);
        }
        for (i = NUMBER_OF_ROUNDS; i > 0; i--)
        {
            rrr_enc_dec_round(ref block, roundKeys, i, ref temp, 0);
        }
        for (i = 0; i < 4; i++)
            temp[i] = block[i];
        for (i = 0; i < 4; i++)
            block[i] = (byte)(block[i + 4] ^ (byte)Marshal.ReadByte(roundKeys, i + 4));
        for (i = 0; i < 4; i++)
            block[i + 4] = temp[i];

        return block;
    }

    public byte[] Decrypt(byte[] block, IntPtr roundKeys)
    {
        byte i;
        byte[] temp = new byte[4] { 0, 0, 0, 0 };
        temp[0] = 8;
        for (i = 0; i < 4; i++)
            block[i] ^= (byte)Marshal.ReadByte(roundKeys, i + 4);
        for (i = 1; i <= NUMBER_OF_ROUNDS; i++)
        {
            rrr_enc_dec_round(ref block, roundKeys, i, ref temp, 1);
        }
        for (i = 0; i < 4; i++)
            temp[i] = block[i];
        for (i = 0; i < 4; i++)
            block[i] = (byte)(block[i + 4] ^ (byte)Marshal.ReadByte(roundKeys, i));
        for (i = 0; i < 4; i++)
            block[i + 4] = temp[i];
        
        return block;
    }

    public static bool CompareArrays(byte[] arr1, byte[] arr2)
    {
        if (arr1.Length != arr2.Length)
            return false;

        for (int i = 0; i < arr1.Length; i++)
        {
            if (arr1[i] != arr2[i])
                return false;
        }

        return true;
    }

    public byte[] EncryptString(byte[] plaintextBytes, byte[] key)
    {

        
        byte[] block = new byte[BLOCK_SIZE];

        int numBlocks = plaintextBytes.Length / BLOCK_SIZE;
        if (plaintextBytes.Length % BLOCK_SIZE != 0)
        {
            numBlocks++;
            Array.Resize(ref plaintextBytes, numBlocks * BLOCK_SIZE);
        }


        _scheduledKey = KeySchedule(key);
        byte[] encrypted_block;
        byte[] ciphertextBytes = new byte[numBlocks * BLOCK_SIZE];

        //encrypted = encript(block);

        for (int i = 0; i < numBlocks; i++)
        {
            Array.Copy(plaintextBytes, i * BLOCK_SIZE, block, 0, BLOCK_SIZE);
            encrypted_block = encript(block);
            Array.Copy(encrypted_block, 0, ciphertextBytes, i * BLOCK_SIZE, BLOCK_SIZE);
            AddStep( "Şifrelenmiş blok "+i, BitConverter.ToString(block));
        }
        //roundKeys.Free();

        // return Convert.ToBase64String(plaintextBytes);
        return ciphertextBytes;
    }

    public byte[] DecryptString(byte[] ciphertext, byte[] key)
    {
        // byte[] ciphertextBytes = Convert.FromBase64String(ciphertext);
            byte[] ciphertextBytes = ciphertext;
        byte[] block = new byte[BLOCK_SIZE];

        int numBlocks = ciphertextBytes.Length / BLOCK_SIZE;
        if (ciphertextBytes.Length % BLOCK_SIZE != 0)
            throw new ArgumentException("Invalid ciphertext length.");

        _scheduledKey = KeySchedule(key);
        byte[] decrypted_block;
        byte[] dectextBytes = new byte[numBlocks * BLOCK_SIZE];

        for (int i = 0; i < numBlocks; i++)
        {
            Array.Copy(ciphertextBytes, i * BLOCK_SIZE, block, 0, BLOCK_SIZE);
            decrypted_block = decript(block);
            Array.Copy(decrypted_block, 0, dectextBytes, i * BLOCK_SIZE, BLOCK_SIZE);
            AddStep("deşifrelenmiş blok " + i, BitConverter.ToString(block));
        }
        // Marshal.FreeHGlobal(roundKeys);

        //string plaintext = Encoding.UTF8.GetString(ciphertextBytes).TrimEnd('\0');
        return dectextBytes;
    }
}
