using Algorithms.Common.Abstract;

namespace Algorithms;

using System;
using System.Text;
using System.Runtime.InteropServices;
using Algorithms.Common.Enums;
using Algorithms.Common.DataTransferObjects;
using System.Diagnostics;
using System.Collections;

public class Zorro : EncryptionAlgorithm
{
    static byte[] s = new byte[256] {
            0xB2, 0xE5, 0x5E, 0xFD, 0x5F, 0xC5, 0x50, 0xBC, 0xDC, 0x4A, 0xFA, 0x88, 0x28, 0xD8, 0xE0, 0xD1,
        0xB5, 0xD0, 0x3C, 0xB0, 0x99, 0xC1, 0xE8, 0xE2, 0x13, 0x59, 0xA7, 0xFB, 0x71, 0x34, 0x31, 0xF1,
        0x9F, 0x3A, 0xCE, 0x6E, 0xA8, 0xA4, 0xB4, 0x7E, 0x1F, 0xB7, 0x51, 0x1D, 0x38, 0x9D, 0x46, 0x69,
        0x53, 0x0E, 0x42, 0x1B, 0x0F, 0x11, 0x68, 0xCA, 0xAA, 0x06, 0xF0, 0xBD, 0x26, 0x6F, 0x00, 0xD9,
        0x62, 0xF3, 0x15, 0x60, 0xF2, 0x3D, 0x7F, 0x35, 0x63, 0x2D, 0x67, 0x93, 0x1C, 0x91, 0xF9, 0x9C,
        0x66, 0x2A, 0x81, 0x20, 0x95, 0xF8, 0xE3, 0x4D, 0x5A, 0x6D, 0x24, 0x7B, 0xB9, 0xEF, 0xDF, 0xDA,
        0x58, 0xA9, 0x92, 0x76, 0x2E, 0xB3, 0x39, 0x0C, 0x29, 0xCD, 0x43, 0xFE, 0xAB, 0xF5, 0x94, 0x23,
        0x16, 0x80, 0xC0, 0x12, 0x4C, 0xE9, 0x48, 0x19, 0x08, 0xAE, 0x41, 0x70, 0x84, 0x14, 0xA2, 0xD5,
        0xB8, 0x33, 0x65, 0xBA, 0xED, 0x17, 0xCF, 0x96, 0x1E, 0x3B, 0x0B, 0xC2, 0xC8, 0xB6, 0xBB, 0x8B,
        0xA1, 0x54, 0x75, 0xC4, 0x10, 0x5D, 0xD6, 0x25, 0x97, 0xE6, 0xFC, 0x49, 0xF7, 0x52, 0x18, 0x86,
        0x8D, 0xCB, 0xE1, 0xBF, 0xD7, 0x8E, 0x37, 0xBE, 0x82, 0xCC, 0x64, 0x90, 0x7C, 0x32, 0x8F, 0x4B,
        0xAC, 0x1A, 0xEA, 0xD3, 0xF4, 0x6B, 0x2C, 0xFF, 0x55, 0x0A, 0x45, 0x09, 0x89, 0x01, 0x30, 0x2B,
        0xD2, 0x77, 0x87, 0x72, 0xEB, 0x36, 0xDE, 0x9E, 0x8C, 0xDB, 0x6C, 0x9B, 0x05, 0x02, 0x4E, 0xAF,
        0x04, 0xAD, 0x74, 0xC3, 0xEE, 0xA6, 0xF6, 0xC7, 0x7D, 0x40, 0xD4, 0x0D, 0x3E, 0x5B, 0xEC, 0x78,
        0xA0, 0xB1, 0x44, 0x73, 0x47, 0x5C, 0x98, 0x21, 0x22, 0x61, 0x3F, 0xC6, 0x7A, 0x56, 0xDD, 0xE7,
        0x85, 0xC9, 0x8A, 0x57, 0x27, 0x07, 0x9A, 0x03, 0xA3, 0x83, 0xE4, 0x6A, 0xA5, 0x2F, 0x79, 0x4F
        };

    static byte[] inv_s = new byte[256] {
            0x3E, 0xBD, 0xCD, 0xF7, 0xD0, 0xCC, 0x39, 0xF5, 0x78, 0xBB, 0xB9, 0x8A, 0x67, 0xDB, 0x31, 0x34,
        0x94, 0x35, 0x73, 0x18, 0x7D, 0x42, 0x70, 0x85, 0x9E, 0x77, 0xB1, 0x33, 0x4C, 0x2B, 0x88, 0x28,
        0x53, 0xE7, 0xE8, 0x6F, 0x5A, 0x97, 0x3C, 0xF4, 0x0C, 0x68, 0x51, 0xBF, 0xB6, 0x49, 0x64, 0xFD,
        0xBE, 0x1E, 0xAD, 0x81, 0x1D, 0x47, 0xC5, 0xA6, 0x2C, 0x66, 0x21, 0x89, 0x12, 0x45, 0xDC, 0xEA,
        0xD9, 0x7A, 0x32, 0x6A, 0xE2, 0xBA, 0x2E, 0xE4, 0x76, 0x9B, 0x09, 0xAF, 0x74, 0x57, 0xCE, 0xFF,
        0x06, 0x2A, 0x9D, 0x30, 0x91, 0xB8, 0xED, 0xF3, 0x60, 0x19, 0x58, 0xDD, 0xE5, 0x95, 0x02, 0x04,
        0x43, 0xE9, 0x40, 0x48, 0xAA, 0x82, 0x50, 0x4A, 0x36, 0x2F, 0xFB, 0xB5, 0xCA, 0x59, 0x23, 0x3D,
        0x7B, 0x1C, 0xC3, 0xE3, 0xD2, 0x92, 0x63, 0xC1, 0xDF, 0xFE, 0xEC, 0x5B, 0xAC, 0xD8, 0x27, 0x46,
        0x71, 0x52, 0xA8, 0xF9, 0x7C, 0xF0, 0x9F, 0xC2, 0x0B, 0xBC, 0xF2, 0x8F, 0xC8, 0xA0, 0xA5, 0xAE,
        0xAB, 0x4D, 0x62, 0x4B, 0x6E, 0x54, 0x87, 0x98, 0xE6, 0x14, 0xF6, 0xCB, 0x4F, 0x2D, 0xC7, 0x20,
        0xE0, 0x90, 0x7E, 0xF8, 0x25, 0xFC, 0xD5, 0x1A, 0x24, 0x61, 0x38, 0x6C, 0xB0, 0xD1, 0x79, 0xCF,
        0x13, 0xE1, 0x00, 0x65, 0x26, 0x10, 0x8D, 0x29, 0x80, 0x5C, 0x83, 0x8E, 0x07, 0x3B, 0xA7, 0xA3,
        0x72, 0x15, 0x8B, 0xD3, 0x93, 0x05, 0xEB, 0xD7, 0x8C, 0xF1, 0x37, 0xA1, 0xA9, 0x69, 0x22, 0x86,
        0x11, 0x0F, 0xC0, 0xB3, 0xDA, 0x7F, 0x96, 0xA4, 0x0D, 0x3F, 0x5F, 0xC9, 0x08, 0xEE, 0xC6, 0x5E,
        0x0E, 0xA2, 0x17, 0x56, 0xFA, 0x01, 0x99, 0xEF, 0x16, 0x75, 0xB2, 0xC4, 0xDE, 0x84, 0xD4, 0x5D,
        0x3A, 0x1F, 0x44, 0x41, 0xB4, 0x6D, 0xD6, 0x9C, 0x55, 0x4E, 0x0A, 0x1B, 0x9A, 0x03, 0x6B, 0xB7
        };
    public Zorro(InputDto inputDto) : base(inputDto)
    {
        
    }

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
    static void PrintInternalState(byte[] state)
    {
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                Console.Write($"{state[(j * 4) + i]:X2} ");
            }
            Console.WriteLine();
        }
        Console.WriteLine();
    }
    static byte MulGaloisField2_8(byte a, byte b)
    {
        byte p = 0;
        byte hi_bit_set;
        byte counter;
        for (counter = 0; counter < 8; counter++)
        {
            if ((b & 1) == 1)
                p ^= a;
            hi_bit_set = (byte)(a & 0x80);
            a <<= 1;
            if (hi_bit_set == 0x80)
                a ^= 0x1b;
            b >>= 1;
        }
        return p;
    }

    static void MixColumn(byte[] column)
    {
        byte[] cpy = new byte[4];
        for (int i = 0; i < 4; i++)
        {
            cpy[i] = column[i];
        }
        column[0] = (byte)(MulGaloisField2_8(cpy[0], 2) ^
                          MulGaloisField2_8(cpy[1], 3) ^
                          MulGaloisField2_8(cpy[2], 1) ^
                          MulGaloisField2_8(cpy[3], 1));
        column[1] = (byte)(MulGaloisField2_8(cpy[0], 1) ^
                          MulGaloisField2_8(cpy[1], 2) ^
                          MulGaloisField2_8(cpy[2], 3) ^
                          MulGaloisField2_8(cpy[3], 1));
        column[2] = (byte)(MulGaloisField2_8(cpy[0], 1) ^
                          MulGaloisField2_8(cpy[1], 1) ^
                          MulGaloisField2_8(cpy[2], 2) ^
                          MulGaloisField2_8(cpy[3], 3));
        column[3] = (byte)(MulGaloisField2_8(cpy[0], 3) ^
                          MulGaloisField2_8(cpy[1], 1) ^
                          MulGaloisField2_8(cpy[2], 1) ^
                          MulGaloisField2_8(cpy[3], 2));
    }

    static void InvMixColumn(byte[] column)
    {
        byte[] cpy = new byte[4];
        for (int i = 0; i < 4; i++)
        {
            cpy[i] = column[i];
        }
        column[0] = (byte)(MulGaloisField2_8(cpy[0], 14) ^
                          MulGaloisField2_8(cpy[1], 11) ^
                          MulGaloisField2_8(cpy[2], 13) ^
                          MulGaloisField2_8(cpy[3], 9));
        column[1] = (byte)(MulGaloisField2_8(cpy[0], 9) ^
                          MulGaloisField2_8(cpy[1], 14) ^
                          MulGaloisField2_8(cpy[2], 11) ^
                          MulGaloisField2_8(cpy[3], 13));
        column[2] = (byte)(MulGaloisField2_8(cpy[0], 13) ^
                          MulGaloisField2_8(cpy[1], 9) ^
                          MulGaloisField2_8(cpy[2], 14) ^
                          MulGaloisField2_8(cpy[3], 11));
        column[3] = (byte)(MulGaloisField2_8(cpy[0], 11) ^
                          MulGaloisField2_8(cpy[1], 13) ^
                          MulGaloisField2_8(cpy[2], 9) ^
                          MulGaloisField2_8(cpy[3], 14));
    }
    static void ZorroMixColumns(byte[] internBuffer)
    {
        byte[] column = new byte[4];
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                column[j] = internBuffer[(i * 4) + j];
            }
            MixColumn(column);
            for (int j = 0; j < 4; j++)
            {
                internBuffer[(i * 4) + j] = column[j];
            }
        }
    }
    static void ZorroInvMixColumns(byte[] internBuffer)
    {
        byte[] column = new byte[4];
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                column[j] = internBuffer[(i * 4) + j];
            }
            InvMixColumn(column);
            for (int j = 0; j < 4; j++)
            {
                internBuffer[(i * 4) + j] = column[j];
            }
        }
    }
    static void ZorroOneRoundEnc(byte[] state, byte round)
    {
        /* SubBytes */
        state[0] = s[state[0]];
        state[4] = s[state[4]];
        state[8] = s[state[8]];
        state[12] = s[state[12]];

        /* Add Constant */
        state[0] = (byte)(state[0] ^ round);
        state[4] = (byte)(state[4] ^ round);
        state[8] = (byte)(state[8] ^ round);
        state[12] = (byte)(state[12] ^ (round << 3));

        /* Shift Rows */
        byte tmp = state[1];
        state[1] = state[5];
        state[5] = state[9];
        state[9] = state[13];
        state[13] = tmp;

        tmp = state[2];
        state[2] = state[10];
        state[10] = tmp;
        tmp = state[6];
        state[6] = state[14];
        state[14] = tmp;

        tmp = state[3];
        state[3] = state[15];
        state[15] = state[11];
        state[11] = state[7];
        state[7] = tmp;

        /* MixColumn */
        ZorroMixColumns(state);
    }
    static void ZorroOneRoundDec(byte[] state, byte round)
    {
        /* Inverse MixColumn */
        ZorroInvMixColumns(state);

        /* Inverse Shift Rows */
        byte tmp = state[13];
        state[13] = state[9];
        state[9] = state[5];
        state[5] = state[1];
        state[1] = tmp;

        tmp = state[2];
        state[2] = state[10];
        state[10] = tmp;
        tmp = state[6];
        state[6] = state[14];
        state[14] = tmp;

        tmp = state[3];
        state[3] = state[7];
        state[7] = state[11];
        state[11] = state[15];
        state[15] = tmp;

        /* Inverse Add Constant */
        state[0] = (byte)(state[0] ^ round);
        state[4] = (byte)(state[4] ^ round);
        state[8] = (byte)(state[8] ^ round);
        state[12] = (byte)(state[12] ^ (round << 3));

        /* Inverse SubBytes */
        state[0] = inv_s[state[0]];
        state[4] = inv_s[state[4]];
        state[8] = inv_s[state[8]];
        state[12] = inv_s[state[12]];
    }
    static void ZorroFourRoundEnc(byte[] state, byte[] key, byte round)
    {
        /* 4 Rounds - KeyAddition */
        int i;
        for (i = 0; i < 4; i++)
        {
            ZorroOneRoundEnc(state, round);
            round++;
        }

        /* Key addition */
        for (i = 0; i < 16; i++)
        {
            state[i] ^= key[i];
        }
    }
    static void ZorroFourRoundDec(byte[] state, byte[] key, byte round)
    {
        /* 4 Rounds - KeyAddition */
        int i;
        for (i = 0; i < 4; i++)
        {
            ZorroOneRoundDec(state, round);
            round--;
        }

        /* Key addition */
        for (i = 0; i < 16; i++)
        {
            state[i] ^= key[i];
        }
    }
    static void ZorroCompleteEnc(byte[] state, byte[] key)
    {
        /* Key Whitening */
        for (int i = 0; i < 16; i++)
        {
            state[i] ^= key[i];
        }

        /* 6 x 4 Rounds of Zorro */
        byte round = 0x01;
        for (int i = 0; i < 6; i++)
        {
            ZorroFourRoundEnc(state, key, round);
            round += 4;
        }
    }
    static void ZorroCompleteDec(byte[] state, byte[] key)
    {
        /* Key Whitening */
        for (int i = 0; i < 16; i++)
        {
            state[i] ^= key[i];
        }

        /* 6 x 4 Rounds of Zorro */
        byte round = 0x18;
        for (int i = 0; i < 6; i++)
        {
            ZorroFourRoundDec(state, key, round);
            round -= 4;
        }
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



        byte[] encrypted_block;
        byte[] ciphertextBytes = new byte[numBlocks * BLOCK_SIZE];

        //encrypted = encript(block);

        for (int i = 0; i < numBlocks; i++)
        {
            Array.Copy(plaintextBytes, i * BLOCK_SIZE, block, 0, BLOCK_SIZE);
            ZorroCompleteEnc(block, key);
            encrypted_block = block;
            Array.Copy(encrypted_block, 0, ciphertextBytes, i * BLOCK_SIZE, BLOCK_SIZE);
            AddStep( "Şifrelenmiş blok "+i, BitConverter.ToString(block));
        }
        //roundKeys.Free();

        // return Convert.ToBase64String(plaintextBytes);
        return ciphertextBytes;
    }
    public int BLOCK_SIZE = 16;    

    public byte[] DecryptString(byte[] ciphertext, byte[] key)
    {
        // byte[] ciphertextBytes = Convert.FromBase64String(ciphertext);
            byte[] ciphertextBytes = ciphertext;
        byte[] block = new byte[BLOCK_SIZE];

        int numBlocks = ciphertextBytes.Length / BLOCK_SIZE;
        if (ciphertextBytes.Length % BLOCK_SIZE != 0)
            throw new ArgumentException("Invalid ciphertext length.");


        byte[] decrypted_block;
        byte[] dectextBytes = new byte[numBlocks * BLOCK_SIZE];

        for (int i = 0; i < numBlocks; i++)
        {
            Array.Copy(ciphertextBytes, i * BLOCK_SIZE, block, 0, BLOCK_SIZE);
            ZorroCompleteDec(block, key);
            decrypted_block = block;
            Array.Copy(decrypted_block, 0, dectextBytes, i * BLOCK_SIZE, BLOCK_SIZE);
            AddStep("deşifrelenmiş blok " + i, BitConverter.ToString(block));
        }

        //string plaintext = Encoding.UTF8.GetString(ciphertextBytes).TrimEnd('\0');
        return dectextBytes;
    }
}
