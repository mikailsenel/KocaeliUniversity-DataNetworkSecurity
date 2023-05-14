using Algorithms.Common.Abstract;

namespace Algorithms;

using System;
using System.Text;
using System.Runtime.InteropServices;

public class RoadRunneR : EncryptionAlgorithm
{
    public RoadRunneR(string text) : base(text)
    {
        
    }

    protected override void Initial(string input)
    {
        byte[] expectedKey = {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
        };

        string message = "Hello World Hello World Hello World Hello World!   !";

        byte[] enc = RoadRunneR.EncryptString(message, expectedKey);
        AddStep( "Şifrelenecek girdi:", BitConverter.ToString(enc));
        Console.WriteLine(BitConverter.ToString(enc));

        string dec = RoadRunneR.DecryptString(enc, expectedKey);
        AddStep( "Şifrelenecek girdi:", dec);
        Console.WriteLine(dec);
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

    static void rrr_L(ref byte[] data)
    {
        byte temp = data[0];
        temp = ROTL(temp);
        temp ^= data[0];
        temp = ROTL(temp);
        data[0] ^= temp;
    }

    static void rrr_SLK(ref byte[] data, IntPtr key_part)
    {
        byte i;
        rrr_sbox(ref data);
        for (i = 0; i < 4; i++)
        {
            rrr_L(ref data);
            data[i] ^= (byte)Marshal.ReadByte(key_part, i);
        }
    }

    static void rrr_enc_dec_round(ref byte[] block, IntPtr roundKey, byte round, ref byte[] key_ctr, byte mode)
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

    public static byte[] Encrypt(byte[] block, IntPtr roundKeys)
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

    public static byte[] Decrypt(byte[] block, IntPtr roundKeys)
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

    public static byte[] EncryptString(string plaintext, byte[] key)
    {
        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        byte[] block = new byte[BLOCK_SIZE];

        int numBlocks = plaintextBytes.Length / BLOCK_SIZE;
        if (plaintextBytes.Length % BLOCK_SIZE != 0)
        {
            numBlocks++;
            Array.Resize(ref plaintextBytes, numBlocks * BLOCK_SIZE);
        }

        GCHandle roundKeys = GCHandle.Alloc(key, GCHandleType.Pinned);
        // IntPtr roundKeys = Marshal.AllocHGlobal(ROUND_KEYS_SIZE);


        byte[] keyCtr = new byte[] { 0 };
        for (int i = 0; i < numBlocks; i++)
        {
            Array.Copy(plaintextBytes, i * BLOCK_SIZE, block, 0, BLOCK_SIZE);
            RoadRunneR.Encrypt(block, roundKeys.AddrOfPinnedObject());
            Array.Copy(block, 0, plaintextBytes, i * BLOCK_SIZE, BLOCK_SIZE);
        }
        roundKeys.Free();

        // return Convert.ToBase64String(plaintextBytes);
        return plaintextBytes;
    }

    public static string DecryptString(byte[] ciphertext, byte[] key)
    {
        // byte[] ciphertextBytes = Convert.FromBase64String(ciphertext);
        byte[] ciphertextBytes = ciphertext;
        byte[] block = new byte[BLOCK_SIZE];

        int numBlocks = ciphertextBytes.Length / BLOCK_SIZE;
        if (ciphertextBytes.Length % BLOCK_SIZE != 0)
            throw new ArgumentException("Invalid ciphertext length.");

        // IntPtr roundKeys = Marshal.AllocHGlobal(ROUND_KEYS_SIZE);
        GCHandle roundKeys = GCHandle.Alloc(key, GCHandleType.Pinned);
        byte[] keyCtr = new byte[] { 0 };
        for (int i = 0; i < numBlocks; i++)
        {
            Array.Copy(ciphertextBytes, i * BLOCK_SIZE, block, 0, BLOCK_SIZE);
            RoadRunneR.Decrypt(block, roundKeys.AddrOfPinnedObject());
            Array.Copy(block, 0, ciphertextBytes, i * BLOCK_SIZE, BLOCK_SIZE);
        }
        // Marshal.FreeHGlobal(roundKeys);
        roundKeys.Free();

        string plaintext = Encoding.UTF8.GetString(ciphertextBytes).TrimEnd('\0');
        return plaintext;
    }
}
