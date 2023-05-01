using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
/*Algoritma tamamlanMAMIŞTIR.*/
namespace Algorithms
{
    public class Piccolo
    {
   public void Initial(string input)
{
    byte[] key = new byte[] { 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0 };

        // Plaintext must be 8 bytes long
        byte[] plaintext = new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };

        Console.WriteLine("Şifrelenecek Metin: " + BitConverter.ToString(plaintext));

        // Encrypt the plaintext
        byte[] ciphertext = Piccolo.Encrypt(key, plaintext);
        Console.WriteLine("Şifreli Metin: " + BitConverter.ToString(ciphertext));

}
// Substitution box (S-box) for Piccolo encryption
    private static readonly byte[] sBox = {
        0x6, 0x4, 0xc, 0x5, 0x0, 0x7, 0x2, 0xe, 0x1, 0xf, 0x3, 0xd, 0x8, 0xa, 0x9, 0xb
    };

    // Permutation box (P-box) for Piccolo encryption
    private static readonly byte[] pBox = {
        0x0, 0x4, 0x8, 0xc, 0x1, 0x5, 0x9, 0xd, 0x2, 0x6, 0xa, 0xe, 0x3, 0x7, 0xb, 0xf
    };

    // Piccolo encryption function
    public static byte[] Encrypt(byte[] key, byte[] plaintext)
    {
        if (key == null || key.Length != 8)
            throw new ArgumentException("Geçersiz key boyutu:  8 byte olmalı");
        if (plaintext == null || plaintext.Length != 8)
            throw new ArgumentException("Geçersiz  metin boyutu: 8 byte olmalı");

        byte[] state = (byte[])plaintext.Clone();

        // Generate round keys
        byte[][] roundKeys = GenerateRoundKeys(key);

        // Perform 31 rounds of encryption
        for (int i = 0; i < 31; i++)
        {
            // Apply S-box to each byte of the state
            for (int j = 0; j < 8; j++)
            {
                state[j] = sBox[state[j] % 16];
            }

            // Apply P-box to the state
            state = ApplyPBox(state);

            // XOR the round key with the state
            state = Xor(state, roundKeys[i]);
        }

        return state;
    }

    // Generate round keys for Piccolo encryption
    private static byte[][] GenerateRoundKeys(byte[] key)
    {
        byte[][] roundKeys = new byte[31][];

        // Initialize round key with key
        roundKeys[0] = key;

        // Generate 31 round keys
        for (int i = 1; i < 31; i++)
        {
            // Rotate left by 61 bits
            byte[] rotatedKey = RotateLeft(key, 61);

            // Apply S-box to each byte of the key
            for (int j = 0; j < 8; j++)
            {
                rotatedKey[j] = sBox[rotatedKey[j] % 16];
            }

            // XOR the round constant with the first byte of the key
            byte roundConstant = (byte)(i & 0x1f);
            rotatedKey[0] ^= roundConstant;

            // XOR the rotated key with the previous round key
            roundKeys[i] = Xor(rotatedKey, roundKeys[i - 1]);

            // Set key to the previous round key
            key = roundKeys[i - 1];
        }
        

        return roundKeys;
     
    }

    private static byte[] ApplyPBox(byte[] state)
    {
        byte[] newState = new byte[8];

        for (int i = 0; i < 8; i++)
        {
            int row = (i >> 2) & 3;
            int col = i & 3;
            int shift = 12 - (4 * row) - col;
            int newIndex = (i + shift) & 7;
            newState[newIndex] = state[i];
        }
    
        return newState;
    }

    // XOR two byte arrays of equal length
    private static byte[] Xor(byte[] a, byte[] b)
    {
        if (a == null || b == null || a.Length != b.Length)
            throw new ArgumentException("Geçersiz arguman: diziler eşit boyda olmalı");

        byte[] result = new byte[a.Length];

        for (int i = 0; i < a.Length; i++)
        {
            result[i] = (byte)(a[i] ^ b[i]);
        }

        return result;
    }

    // Rotate a byte array left by a given number of bits
    private static byte[] RotateLeft(byte[] input, int bits)
    {
        byte[] output = new byte[input.Length];
        int bytes = bits / 8;
        int shift = bits % 8;

        for (int i = 0; i < input.Length - bytes; i++)
{
    int newIndex = (i + input.Length - bytes) % input.Length;
    output[newIndex] = (byte)(input[i] << shift);
    if (shift > 0 && newIndex < input.Length - 1)
    {
        output[newIndex] |= (byte)(input[i + 1] >> (8 - shift));
    }
}

        return output;
    }
}

    }
