using Algorithms.Common.Abstract;

namespace Algorithms;

using System;
using System.Text;
using System.Runtime.InteropServices;
using Algorithms.Common.Enums;
using Algorithms.Common.DataTransferObjects;
using System.Diagnostics;
using System.Collections;

public class Twine : EncryptionAlgorithm
{
    public Twine(InputDto inputDto) : base(inputDto)
    {

    }

    public static byte[] sbox = new byte[] { 0x0C, 0x00, 0x0F, 0x0A, 0x02, 0x0B, 0x09, 0x05, 0x08, 0x03, 0x0D, 0x07, 0x01, 0x0E, 0x06, 0x04 };

    public static byte[] shuf = new byte[] { 5, 0, 1, 4, 7, 12, 3, 8, 13, 6, 9, 2, 15, 10, 11, 14 };
    public static byte[] shufinv = new byte[] { 1, 2, 11, 6, 3, 0, 9, 4, 7, 10, 13, 14, 5, 8, 15, 12 };
    public static byte[] roundconst = new byte[] {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x03, 0x06, 0x0c, 0x18, 0x30, 0x23, 0x05, 0x0a, 0x14, 0x28, 0x13, 0x26,
    0x0f, 0x1e, 0x3c, 0x3b, 0x35, 0x29, 0x11, 0x22, 0x07, 0x0e, 0x1c, 0x38, 0x33, 0x25, 0x09, 0x12, 0x24, 0x0b,
    };


    public static int[,] rk = new int[36, 8];

    protected override void Initial(string inputKey, DataTypes inputTypes, DataTypes outputTypes)
    {

        byte[] key = Encoding.ASCII.GetBytes(inputKey);
        byte[] ciphertext;
        byte[] plaintext;

        if (inputKey.Length != 16)
        {
            throw new ArgumentException("Key uzunluğu (16 byte, 128 bit) olmalı.");
        }

        string plaintextR = StringValue;
        Console.WriteLine("Şifrelenecek girdi: " + plaintextR);
        AddStep("Şifrelenecek girdi", plaintextR);





        if (inputTypes == DataTypes.Hex)
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
    const int BLOCK_SIZE = 8;
    const int KEY_SIZE = 16;
    public byte[] EncryptString(byte[] plaintextBytes, byte[] key)
    {


        byte[] block = new byte[BLOCK_SIZE];

        int numBlocks = plaintextBytes.Length / BLOCK_SIZE;
        if (plaintextBytes.Length % BLOCK_SIZE != 0)
        {
            numBlocks++;
            Array.Resize(ref plaintextBytes, numBlocks * BLOCK_SIZE);
        }


        ExpandKeys128(key);
        byte[] encrypted_block;
        byte[] ciphertextBytes = new byte[numBlocks * BLOCK_SIZE];

        //encrypted = encript(block);

        for (int i = 0; i < numBlocks; i++)
        {
            Array.Copy(plaintextBytes, i * BLOCK_SIZE, block, 0, BLOCK_SIZE);
            encrypted_block = Encrypt(block);
            Array.Copy(encrypted_block, 0, ciphertextBytes, i * BLOCK_SIZE, BLOCK_SIZE);
            AddStep("Şifrelenmiş blok " + i, BitConverter.ToString(block));
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

        ExpandKeys128(key);
        byte[] decrypted_block;
        byte[] dectextBytes = new byte[numBlocks * BLOCK_SIZE];

        for (int i = 0; i < numBlocks; i++)
        {
            Array.Copy(ciphertextBytes, i * BLOCK_SIZE, block, 0, BLOCK_SIZE);
            decrypted_block = Decrypt(block);
            Array.Copy(decrypted_block, 0, dectextBytes, i * BLOCK_SIZE, BLOCK_SIZE);
            AddStep("deşifrelenmiş blok " + i, BitConverter.ToString(block));
        }
        // Marshal.FreeHGlobal(roundKeys);

        //string plaintext = Encoding.UTF8.GetString(ciphertextBytes).TrimEnd('\0');
        return dectextBytes;
    }
    public static byte[] Decrypt(byte[] src)
    {
        byte[] x = new byte[16];
        byte[] dst = new byte[8];
        int i = 0;
        for (i = 0; i < src.Length; i++)
        {
            x[2 * i] = (byte)(src[i] >> 4);
            x[2 * i + 1] = (byte)(src[i] & 0x0f);
        }
        i = 35;
        for (i = 35; i >= 1; i--)
        {
            for (int j = 0; j < 8; j++)
            {
                x[2 * j + 1] ^= sbox[x[2 * j] ^ rk[i, j]];
            }

            byte[] xnext = new byte[16];
            for (int h = 0; h < 16; h++)
            {
                xnext[shufinv[h]] = x[h];
            }
            Array.Copy(xnext, x, x.Length);
        }

        i = 0;
        for (int j = 0; j < 8; j++)
        {
            x[2 * j + 1] ^= sbox[x[2 * j] ^ rk[i, j]];
        }

        for (i = 0; i < 8; i++)
        {
            dst[i] = (byte)(x[2 * i] << 4 | x[2 * i + 1]);
        }
        return dst;
    }

    public static void ExpandKeys128(byte[] key)
    {
        int[] wk = new int[32];

        for (int i = 0; i < key.Length; i++)
        {
            wk[2 * i] = key[i] >> 4;
            wk[2 * i + 1] = key[i] & 0x0f;
        }

        for (int i = 0; i < 35; i++)
        {


            rk[i, 0] = wk[2];
            rk[i, 1] = wk[3];
            rk[i, 2] = wk[12];
            rk[i, 3] = wk[15];
            rk[i, 4] = wk[17];
            rk[i, 5] = wk[18];
            rk[i, 6] = wk[28];
            rk[i, 7] = wk[31];

            wk[1] ^= sbox[wk[0]];
            wk[4] ^= sbox[wk[16]];
            wk[23] ^= sbox[wk[30]];
            int con = roundconst[i];
            wk[7] ^= con >> 3;
            wk[19] ^= con & 7;

            int tmp0 = wk[0];
            int tmp1 = wk[1];
            int tmp2 = wk[2];
            int tmp3 = wk[3];

            for (int j = 0; j < 7; j++)
            {
                int fourj = j * 4;
                wk[fourj] = wk[fourj + 4];
                wk[fourj + 1] = wk[fourj + 5];
                wk[fourj + 2] = wk[fourj + 6];
                wk[fourj + 3] = wk[fourj + 7];
            }
            wk[28] = tmp1;
            wk[29] = tmp2;
            wk[30] = tmp3;
            wk[31] = tmp0;
        }

        rk[35, 0] = wk[2];
        rk[35, 1] = wk[3];
        rk[35, 2] = wk[12];
        rk[35, 3] = wk[15];
        rk[35, 4] = wk[17];
        rk[35, 5] = wk[18];
        rk[35, 6] = wk[28];
        rk[35, 7] = wk[31];
    }

    public static byte[] Encrypt(byte[] src)
    {
        byte[] x = new byte[16];
        byte[] dst = new byte[8];

        int i = 0;

        for (i = 0; i < src.Length; i++)
        {
            x[2 * i] = (byte)(src[i] >> 4);
            x[2 * i + 1] = (byte)(src[i] & 0x0f);
        }

        i = 0;
        for (i = 0; i < 35; i++)
        {
            for (int j = 0; j < 8; j++)
            {
                x[2 * j + 1] ^= sbox[x[2 * j] ^ rk[i, j]];
            }

            byte[] xnext = new byte[16];
            for (int h = 0; h < 16; h++)
            {
                xnext[shuf[h]] = x[h];
            }

            Array.Copy(xnext, x, x.Length);
        }

        i = 35;
        for (int j = 0; j < 8; j++)
        {
            x[2 * j + 1] ^= sbox[x[2 * j] ^ rk[i, j]];
        }

        for (i = 0; i < 8; i++)
        {
            dst[i] = (byte)(x[2 * i] << 4 | x[2 * i + 1]);
        }
        return dst;
    }


}

