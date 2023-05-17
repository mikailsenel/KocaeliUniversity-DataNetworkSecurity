using Algorithms.Common.Abstract;
using Algorithms.Common.DataTransferObjects;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Text;
using static System.Runtime.InteropServices.JavaScript.JSType;
//Decyrption metodu yanlış çalışıyor
namespace Algorithms
{
    public class Piccolo : EncryptionAlgorithm
    {
        public Piccolo(string text) : base(text)
        {

        }
public  string GetBinaryString(byte[] data)
{
    StringBuilder binaryString = new StringBuilder();
    foreach (byte b in data)
    {
        string binary = Convert.ToString(b, 2).PadLeft(8, '0');
        binaryString.Append(binary);
    }
    return binaryString.ToString();
}
        protected override void Initial(string input)
        {
            const int MaxInputLength = 16; // 16 byte = 128 bit
            byte[] key = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
        byte[] plaintext = new byte[] { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
            // 128 bit üzerinde veri girişi kontrolü
            if (plaintext.Length > MaxInputLength)
            {
                Console.WriteLine("Hata: Giriş metni 128 bit (16 byte) üzerinde olamaz.");
                AddStep("Hata: Giriş metni 128 bit (16 byte) üzerinde olamaz.", BitConverter.ToString(plaintext));
                return;
            }

            Console.WriteLine("Şifrelenecek Metin: " + BitConverter.ToString(plaintext).Replace("-", ""));
    AddStep("Şifrelenecek Metin: " , BitConverter.ToString(plaintext).Replace("-", ""));
    Console.WriteLine("Şifrelenecek Metin binary gösterimi: " + GetBinaryString(plaintext));
    AddStep("Şifrelenecek Metin binary gösterimi: " , GetBinaryString(plaintext));
    byte[] ciphertext = Encrypt(key, plaintext);
    AddStep("Şifrelenmiş Metin: " , BitConverter.ToString(ciphertext).Replace("-", ""));
    Console.WriteLine("Şifrelenmiş Metin: " + BitConverter.ToString(ciphertext).Replace("-", ""));
    AddStep("Şifrelenmiş Metin binary gösterimi: " , GetBinaryString(ciphertext));
    Console.WriteLine("Şifrelenmiş Metin binary gösterimi: " + GetBinaryString(ciphertext));

    byte[] decryptedText =Decrypt(key, ciphertext);
    Console.WriteLine("Çözülmüş Metin: " + BitConverter.ToString(decryptedText).Replace("-", ""));
    AddStep("Çözülmüş Metin: " , BitConverter.ToString(decryptedText).Replace("-", ""));
    Console.WriteLine("Çözülmüş Metin binary gösterimi: " + GetBinaryString(decryptedText));
     AddStep("Çözülmüş Metin binary gösterimi: " , GetBinaryString(decryptedText));
            }

          
 private readonly byte[] sBox = {
            0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5,
            0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7,
            0x3, 0x8, 0xC, 0xA, 0xF, 0x7, 0x1, 0xD,
            0x9, 0x5, 0x6, 0x2, 0x0, 0x4, 0xB, 0xE,
            0xE, 0xC, 0x4, 0xB, 0x2, 0x1, 0xF, 0x3,
            0x0, 0x9, 0xA, 0x5, 0x8, 0xD, 0x7, 0x6,
            0xB, 0x3, 0x5, 0x8, 0x2, 0xF, 0xA, 0xD,
            0xE, 0x1, 0x7, 0x4, 0xC, 0x9, 0x0, 0x6,
            0x4, 0xB, 0xA, 0x0, 0x7, 0x2, 0x1, 0xD,
            0x3, 0x6, 0x8, 0x5, 0x9, 0xC, 0xF, 0xE,
            0xD, 0xB, 0x4, 0x1, 0x3, 0xF, 0x5, 0x9,
            0x0, 0xA, 0xE, 0x7, 0x6, 0x8, 0x2, 0xC,
            0x1, 0xF, 0xC, 0x8, 0x7, 0x6, 0xB, 0x0,
            0x5, 0xA, 0xD, 0x9, 0xE, 0x2, 0x3, 0x4,
            0xD, 0xC, 0xB, 0x7, 0xE, 0xA, 0x4, 0x2,
            0x9, 0xF, 0x0, 0x5, 0x8, 0x3, 0x6, 0x1
        };


        private  readonly byte[] pBox = {
        58, 50, 42, 34, 26, 18, 10, 2,
         60, 52, 44, 36, 28, 20, 12, 4,
         62, 54, 46, 38, 30, 22, 14, 6,
         64, 56, 48, 40, 32, 24, 16, 8,
         57, 49, 41, 33, 25, 17, 9, 1,
         59, 51, 43, 35, 27, 19, 11, 3,
         61, 53, 45, 37, 29, 21, 13, 5,
         63, 55, 47, 39, 31, 23, 15, 7
        };

        private  byte[][] GenerateRoundKeys(byte[] key)
        {
            byte[][] roundKeys = new byte[32][];
            roundKeys[0] = key;

            for (int i = 1; i < 32; i++)
            {
                byte[] rotatedKey = RotateLeft(roundKeys[i - 1], 61);

                for (int j = 0; j < 8; j++)
                {
                    rotatedKey[j] = sBox[rotatedKey[j] & 0x0F];
                }

                byte roundConstant = (byte)(i & 0x1F);
                rotatedKey[0] ^= roundConstant;

                roundKeys[i] = Xor(rotatedKey, roundKeys[i - 1]);
            }

            return roundKeys;
        }

private  byte[] RotateLeft(byte[] array, int count)
        {
            int shift = count % 8;
            byte[] result = new byte[array.Length];
            for (int i = 0; i < array.Length; i++)
            {
                result[i] = (byte)((array[i] << shift) | (array[(i + 1) % array.Length] >> (8 - shift)));
            }
            return result;
        }

public  byte[] Encrypt(byte[] key, byte[] plaintext)
{
    if (key == null || key.Length != 8)
        throw new ArgumentException("Geçersiz Key büyüklüğü: Key 8 byte olmalı");
    if (plaintext == null || plaintext.Length != 8)
        throw new ArgumentException("Geçersiz şifrelenmiş text bouyutu: şifrelenmiş text bouyutu 8 byte olmalı");

    byte[] state = (byte[])plaintext.Clone();

    // Generate round keys
    byte[][] roundKeys = GenerateRoundKeys(key);

    // Encryption: 31 transformation steps
    for (int i = 0; i < 31; i++)
    {
        // Apply S-box to each byte of the state
        for (int j = 0; j < state.Length; j++)
        {
            state[j] = (byte)((sBox[state[j] >> 4] << 4) | sBox[state[j] & 0x0F]);
        }

        // Apply P-box to the state
        state = ApplyPBox(state);

        // XOR the round key with the state
        state = Xor(state, roundKeys[i]);
    }

    return state;
}
public  byte[] Decrypt(byte[] key, byte[] ciphertext)
{
    if (key == null || key.Length != 8)
        throw new ArgumentException("Geçersiz Key büyüklüğü: Key 8 byte olmalı");
    if (ciphertext == null || ciphertext.Length != 8)
        throw new ArgumentException("Geçersiz şifrelenmiş text bouyutu: şifrelenmiş text bouyutu 8 byte olmalı");

    byte[] state = (byte[])ciphertext.Clone();

    // Generate round keys
    byte[][] roundKeys = GenerateRoundKeys(key);

    for (int i = 30; i >= 0; i--)
    {
        // XOR the round key with the state
        state = Xor(state, roundKeys[i]);

        // Apply the inverse P-box to the state
        state = ApplyInversePBox(state);

        // Apply the inverse S-box to each byte of the state
        for (int j = 0; j < state.Length; j++)
        {
            state[j] = (byte)((sBox[state[j] >> 4] << 4) | sBox[state[j] & 0x0F]);
        }
    }

    return state;
}

        private  byte[] ApplyPBox(byte[] state)
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

  private  byte[] ApplyInversePBox(byte[] state)
{
    byte[] newState = new byte[8];

    for (int i = 0; i < 8; i++)
    {
        int row = (i >> 2) & 3;
        int col = i & 3;
        int shift = (col * 4) + row;
        int newIndex = (i - shift + 32) % 8;
        newState[newIndex] = state[i];
    }

    return newState;
}
        private  byte[] Xor(byte[] a, byte[] b)
        {
            byte[] result = new byte[a.Length];
            for (int i = 0; i < a.Length; i++)
            {
                result[i] = (byte)(a[i] ^ b[i]);
            }
            return result;
        }
        private byte InverseSBox(byte value)
        {
            for (byte i = 0; i < 16; i++)
            {
                if (sBox[i] == value)
                {
                    return i;
                }
            }

            throw new ArgumentException("Invalid S-box value");
        }
    }
}