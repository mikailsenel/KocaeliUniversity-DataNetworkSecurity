using Algorithms.Common.Abstract;
using System;
using System.Text;

namespace Algorithms;
using Algorithms.Common.DataTransferObjects;
using Algorithms.Common.Enums;

// RECTANGLE is an iterated block cipher. The block length is 64 bits, and the key length is 80 or 128 bits.


public class Rectangle: EncryptionAlgorithm
{
    public Rectangle(InputDto inputDto) : base(inputDto)
    {

    }

    protected override void Initial(string inputKey, DataTypes inputTypes, DataTypes outputTypes)
    {
        ushort[] Key = RectangleCipher.stringTouShortArray(inputKey);
        RectangleCipher rec = new RectangleCipher(
            RectangleCipher.stringTouShortArray(StringValue),
            Key
        );

        // --------------------------------------------------
        Console.WriteLine($"Şifrelenecek girdi: {StringValue}");
        AddStep( "Şifrelenecek girdi:", StringValue);

        ushort[] cipher1 = rec.EncryptString(Key, StringValue);
        Console.WriteLine($"cipher: {BitConverter.ToString(RectangleCipher.uShortArrayToBytes(cipher1))}");

        string plain1    = rec.DecryptString(Key, cipher1);
        Console.WriteLine($"plain: {plain1}");
    }
}

public class RectangleCipher
{
    public ushort[] plainText;
    public ushort[] cipherText;
    public ushort[] key; // private
    public ushort[] mainKey; // private
    public ushort rc; // private

    public void printdbg() {
        Console.WriteLine(
            $"P: {PrettyUshortArr(this.plainText)} " +
            $"C: {PrettyUshortArr(this.cipherText)} " +
            $"K: {PrettyUshortArr(this.key)} " +
            $"M: {PrettyUshortArr(this.mainKey)} " +
            $"R: {this.rc} "
        );
    }

    public RectangleCipher(ushort[] plainText, ushort[] key)
    {
        this.plainText = new ushort[plainText.Length];
        Array.Copy(plainText, this.plainText, plainText.Length);

        this.cipherText = new ushort[plainText.Length];
        Array.Copy(plainText, this.cipherText, plainText.Length);

        this.key = new ushort[key.Length];
        Array.Copy(key, this.key, key.Length);

        this.mainKey = new ushort[key.Length];
        Array.Copy(key, this.mainKey, key.Length);

        this.rc = 0;
    }

    private ushort Clsh(ushort num, int shift)
    {
        string newNum = Convert.ToString(num, 2).PadLeft(16, '0');
        string shiftedNum = newNum.Substring(shift) + newNum.Substring(0, shift);
        return Convert.ToUInt16(shiftedNum, 2);
    }

    private void GenerateRC(ref ushort rc)
    {
        if (rc == 0)
        {
            rc = 1;
        }
        else
        {
            ushort rc0 = (ushort)((rc & 0x10) ^ (rc & 0x04));
            rc <<= 1;
            rc &= 0x1f;
            rc |= rc0;
        }
        this.rc = rc;
    }

    private ushort SBox(ushort num)
    {
        ushort[] sBoxTable =
        {
            0x06, 0x05, 0x0c, 0x0a, 0x01, 0x0e, 0x07, 0x09,
            0x0b, 0x00, 0x03, 0x0d, 0x08, 0x0f, 0x04, 0x02
        };
        return sBoxTable[num];
    }

    private ushort InverseSBox(ushort num)
    {
        ushort[] sBoxTable =
        {
            0x09, 0x04, 0x0f, 0x0a, 0x0e, 0x01, 0x00, 0x06,
            0x0c, 0x07, 0x03, 0x08, 0x02, 0x0b, 0x05, 0x0d
        };
        return sBoxTable[num];
    }

    private ushort[] GenerateRoundKey(bool final = false)
    {
        ushort[] roundKey = new ushort[key.Length];
        Array.Copy(key, roundKey, key.Length);

        if (!final)
        {
            SubColumn(ref key, 4);

            ushort row0 = key[0];
            key[0] = (ushort)(Clsh(key[0], 8) ^ key[1]);
            key[1] = key[2];
            key[2] = key[3];
            key[3] = (ushort)(Clsh(key[3], 12) ^ key[4]);
            key[4] = row0;

            ushort lowerBits5 = (ushort)(key[0] & 0x0000001f);
            lowerBits5 ^= rc;
            key[0] = (ushort)((key[0] & 0xffffffe0) | lowerBits5);
        }
       
        return roundKey;
    }

    private void AddRoundKey(ushort[] roundKey)
    {
        for (int i = 0; i < 4; i++)
        {
            cipherText[i] ^= roundKey[i];
        }
    }

    private void SubColumn(ref ushort[] state, int cols = 16, Func<ushort, ushort> sBox = null)
    {
        if (sBox == null)
        {
            sBox = SBox;
        }

        for (int i = 0; i < cols; i++)
        {
            ushort colVal = 0;
            ushort[] keyBits = new ushort[4];

            for (int j = 0; j < 4; j++)
            {
                keyBits[j] = (ushort)((state[j] >> i) & 1);
                colVal |= (ushort)(keyBits[j] << j);
            }

            colVal = sBox(colVal);

            for (int j = 0; j < 4; j++)
            {
                ushort colBit = (ushort)((colVal >> j) & 1);
                state[j] ^= (ushort)((colBit ^ keyBits[j]) << i);
            }
        }
    }

    private void ShiftRow(int inv = 0)
    {
        cipherText[1] = Clsh(cipherText[1], Math.Abs(inv - 1));
        cipherText[2] = Clsh(cipherText[2], Math.Abs(inv - 12));
        cipherText[3] = Clsh(cipherText[3], Math.Abs(inv - 13));
    }

    public void Encrypt()
    {
        for (int i = 0; i < 25; i++)
        {
            GenerateRC(ref rc);
            ushort[] roundKey = GenerateRoundKey();
            AddRoundKey(roundKey);
            SubColumn(ref cipherText);
            ShiftRow();
        }

        ushort[] finalRoundKey = GenerateRoundKey(true);
        AddRoundKey(finalRoundKey);
    }

    private ushort[][] SaveInverseKeys()
    {
        ushort[][] roundKeys = new ushort[26][];
        rc = 0;

        for (int i = 0; i < 25; i++)
        {
            GenerateRC(ref rc);
            roundKeys[i] = GenerateRoundKey();
        }

        roundKeys[25] = GenerateRoundKey(true);
        return roundKeys;
    }

    public void Decrypt()
    {
        // key = mainKey;
        Array.Copy(this.mainKey, key, key.Length);

        ushort[][] roundKeys = SaveInverseKeys();

        for (int i = 25; i >= 1; i--)
        {
            ushort[] roundKey = roundKeys[i];
            AddRoundKey(roundKey);
            ShiftRow(16);
            SubColumn(ref cipherText, 16, InverseSBox);
        }

        ushort[] finalRoundKey = roundKeys[0];
        AddRoundKey(finalRoundKey);
        
        rc = 0;
    }

    public static string PrettyUshortArr(ushort[] arr) {
        string texttmp = "";
        foreach (ushort row in arr)
        {
            texttmp += row.ToString("x4");
        }
        return texttmp;
    }

    public static string uShortArrayToString(ushort[] arr) {
        char[] charArray = new char[arr.Length];
        Array.Copy(arr, charArray, arr.Length);
        return new String(charArray);
    }

    public static ushort[] stringTouShortArray(string str) {
        ushort[] uShortArray = str.Select(c => (ushort)c).ToArray();
        return uShortArray;
    }

    public static byte[] uShortArrayToBytes(ushort[] arr) {
        byte[] target = new byte[arr.Length * 2]; 
        Buffer.BlockCopy(arr, 0, target, 0, arr.Length * 2);
        return target;
    }


    public ushort[] EncryptString(ushort[] key, string plaintext)
    {
        RectangleCipher rec;
        List<ushort> ciphertext = new List<ushort>();
        ushort[] _plaintext = RectangleCipher.stringTouShortArray(plaintext);

        int blockSize = 4;
        int totalBlocks = (int)Math.Ceiling((double)_plaintext.Length / blockSize);

        for (int blockIndex = 0; blockIndex < totalBlocks; blockIndex++)
        {
            int startIndex = blockIndex * blockSize;
            int endIndex = Math.Min(startIndex + blockSize, _plaintext.Length);
            int blockLength = endIndex - startIndex;

            ushort[] block = new ushort[blockSize];
            Array.Copy(_plaintext, startIndex, block, 0, blockLength);

            rec = new RectangleCipher(block, key);
            rec.Encrypt();
            ciphertext.AddRange(rec.cipherText);
        }

        return ciphertext.ToArray();
    }

    public string DecryptString(ushort[] key, ushort[] ciphertext)
    {
        RectangleCipher rec;
        List<ushort> plaintextBytes = new List<ushort>();
        // ushort[] _ciphertext = StringTouShortArray(ciphertext);


        int blockSize = 4;
        int totalBlocks = ciphertext.Length / blockSize;

        for (int blockIndex = 0; blockIndex < totalBlocks; blockIndex++)
        {
            int startIndex = blockIndex * blockSize;
            ushort[] block = new ushort[blockSize];
            Array.Copy(ciphertext, startIndex, block, 0, blockSize);

            rec = new RectangleCipher(block, key);
            rec.Decrypt();
            plaintextBytes.AddRange(rec.cipherText);
        }

        // return Encoding.UTF8.GetString();
        return RectangleCipher.uShortArrayToString(plaintextBytes.ToArray());
    }
}

