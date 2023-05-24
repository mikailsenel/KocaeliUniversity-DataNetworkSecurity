using Algorithms.Common.Abstract;
using System.Text;
using System;

namespace Algorithms;

// ----------------------------------------------------------------
// TAMAMLANDI
// ----------------------------------------------------------------

public class Prince : EncryptionAlgorithm
{
    public Prince(string text) : base(text)
    {

    }


    protected override void Initial(string input,string inputKey)
    {
        byte[] key = { 0x01, 0xc4, 0x41, 0x63, 0x8d, 0xcb, 0x70, 0xa6, 0x01, 0xc4, 0x41, 0x63, 0x8d, 0xcb, 0x70, 0xa6 };
        byte[] data = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
        string datastr = input;
        AddStep("Şifrelenecek Metin", datastr);

        // Console.WriteLine(BitConverter.ToString(data).Replace("-", " "));

        // byte[] encrypted = this.Encrypt(key, data);
        // byte[] decrypted = this.Decrypt(key, encrypted);
        // this.PrintByteArray(encrypted);
        // this.PrintByteArray(decrypted);
        // Console.WriteLine(BitConverter.ToString(encrypted).Replace("-", " "));
        // Console.WriteLine(BitConverter.ToString(decrypted).Replace("-", " "));

        byte[] strencrypted = this.EncryptString(key, datastr);
        AddStep("Şifrelenmiş Metin", BitConverter.ToString(strencrypted));
        Console.WriteLine(BitConverter.ToString(strencrypted));

        // string strdecrypted = this.DecryptString(key, strencrypted);
        // AddStep("Deşifrelenmiş Metin: ", strdecrypted);
        // Console.WriteLine(strdecrypted);

        // Console.WriteLine(strdecrypted);
    }

    private byte[] SBOX = new byte[]
    {
        0x0B, 0x0F, 0x03, 0x02, 0x0A, 0x0C, 0x09, 0x01,
        0x06, 0x07, 0x08, 0x00, 0x0E, 0x05, 0x0D, 0x04
    };

    private byte[] INVSBOX = new byte[]
    {
        0x0B, 0x07, 0x03, 0x02, 0x0F, 0x0D, 0x08, 0x09,
        0x0A, 0x06, 0x04, 0x00, 0x05, 0x0E, 0x0C, 0x01
    };

    private byte[] RC = new byte[]
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x31, 0x91, 0xa8, 0xe2, 0x30, 0x07, 0x37, 0x44,
        0x4a, 0x90, 0x83, 0x22, 0x92, 0xf9, 0x13, 0x0d,
        0x80, 0xe2, 0xaf, 0x89, 0xce, 0xe4, 0xc6, 0x98,
        0x54, 0x82, 0x12, 0x6e, 0x83, 0x0d, 0x31, 0x77,
        0xeb, 0x45, 0x66, 0xfc, 0x43, 0x9e, 0xc0, 0xc6,
        0xe7, 0x8f, 0xf4, 0x87, 0xdf, 0x59, 0xc5, 0x1b,
        0x58, 0x48, 0x80, 0x15, 0x1f, 0xca, 0x34, 0xaa,
        0x8c, 0x28, 0x3d, 0xf2, 0x52, 0x23, 0xc3, 0x45,
        0x46, 0x5a, 0x11, 0x59, 0x0e, 0x3e, 0x16, 0xd0,
        0x3d, 0x5b, 0x3a, 0x99, 0xac, 0xc0, 0x32, 0x99,
        0x0c, 0xca, 0x92, 0x7b, 0x9c, 0xc7, 0x05, 0xdd
    };

    public byte[] Cipher(byte[] extendedKey, byte[] datablock)
    {
        // Key whitening with k_0
        for (int i = 0; i < 8; i++)
        {
            datablock[i] ^= extendedKey[i];
        }

        // Beginning of actual cipher
        datablock = AddKey(extendedKey, datablock);
        AddStep("İlk XOR işlemi", BitConverter.ToString(datablock));

        // PrintByteArray(datablock);

        // Five forward rounds
        for (int i = 1; i <= 5; i++)
        {
            datablock = SubNibbles(datablock);
            datablock = MLayer(datablock);
            datablock = AddRoundConstant(i, datablock);
            datablock = AddKey(extendedKey, datablock);
            AddStep("Round işlemi 5/"+i, BitConverter.ToString(datablock));
        }

        // Middle round
        datablock = SubNibbles(datablock);
        datablock = MPrimeLayer(datablock);
        datablock = InvSubNibbles(datablock);
        AddStep("Middle round", BitConverter.ToString(datablock));

        // Five inverse rounds
        for (int i = 6; i <= 10; i++)
        {
            datablock = AddKey(extendedKey, datablock);
            datablock = AddRoundConstant(i, datablock);
            datablock = InvMLayer(datablock);
            datablock = InvSubNibbles(datablock);
            AddStep("Inverse rounds 10/"+i, BitConverter.ToString(datablock));
        }

        datablock = AddRoundConstant(11, datablock);
        datablock = AddKey(extendedKey, datablock);
        // End of actual cipher

        // Key whitening with k'_0
        for (int i = 0; i < 8; i++)
        {
            datablock[i] ^= extendedKey[i + 8];
        }
        AddStep("Key whitening", BitConverter.ToString(datablock));
        // PrintByteArray(datablock);

        return datablock;
    }


    private byte[] ExtendKey(byte[] key)
    {
        byte[] newKey = new byte[24];

        for (int i = 0; i < 8; i++)
        {
            // k_0 stays the same
            newKey[i] = key[i];
            // k'_0 is a k_0 rotated right one bit and XORed with the last bit
            newKey[i + 8] = (byte)((key[i] >> 1) | (key[(i + 1) % 8] >> 7));
            // k_1 stays the same
            newKey[i + 16] = key[i + 8];
        }

        newKey[15] ^= (byte)(key[7] & 0x10);

        return newKey;
    }

    private byte[] ShiftRows(byte[] data)
    {
        byte[] temp = new byte[data.Length];
        byte[] newdata = new byte[data.Length];
        Array.Copy(data, temp, data.Length); // copy the state into a temporary holder
        
        int[] perm = new int[] { 0, 5, 2, 7, 4, 1, 6, 3 };
        
        for (int i = 0; i < 8; i++)
        {
            int j = (i + 2) % 8;
            newdata[i] = (byte)((temp[perm[i]] & 0x0F) | (data[perm[j]] & 0xF0));
        }
        // PrintByteArray(newdata);
        return newdata;
    }

    private byte[] InvShiftRows(byte[] data)
    {
        byte[] newdata = new byte[data.Length];
        byte[] temp = new byte[data.Length];
        Array.Copy(data, temp, data.Length); // copy the state into a temporary holder
        
        int[] perm = new int[] { 0, 5, 2, 7, 4, 1, 6, 3 };
        
        for (int i = 0; i < 8; i++)
        {
            int index = perm[(i + 6) % 8];
            newdata[i] = (byte)((temp[perm[i]] & 0x0F) | (data[index] & 0xF0));
        }
        // PrintByteArray(newdata);
        
        return newdata;
    }

    private byte[] SubNibbles(byte[] data)
    {
        for (int i = 0; i < data.Length; i++)
        {
            byte upperNibble = (byte)(data[i] >> 4);
            byte lowerNibble = (byte)(data[i] & 0x0F);
            
            data[i] = (byte)((SBOX[upperNibble] << 4) | SBOX[lowerNibble]);
        }
        
        return data;
    }

    private byte[] InvSubNibbles(byte[] data)
    {
        for (int i = 0; i < data.Length; i++)
        {
            byte upperNibble = (byte)(data[i] >> 4);
            byte lowerNibble = (byte)(data[i] & 0x0F);
            
            data[i] = (byte)((INVSBOX[upperNibble] << 4) | INVSBOX[lowerNibble]);
        }
        
        return data;
    }

    private byte[] MPrimeLayer(byte[] data)
    {
        byte temp;
        
        // M0
        temp = data[0];
        data[0] = (byte)((temp & 0xD7) ^ (data[1] & 0x7D) ^ (temp >> 4 & 0x0B) ^ (data[1] >> 4 & 0x0E) ^ (temp << 4 & 0xB0) ^ (data[1] << 4 & 0xE0));
        data[1] = (byte)((temp & 0x7D) ^ (data[1] & 0xD7) ^ (temp >> 4 & 0x0E) ^ (data[1] >> 4 & 0x0B) ^ (temp << 4 & 0xE0) ^ (data[1] << 4 & 0xB0));
        
        // M1
        temp = data[2];
        data[2] = (byte)((temp & 0xEB) ^ (data[3] & 0xBE) ^ (temp >> 4 & 0x0D) ^ (data[3] >> 4 & 0x07) ^ (temp << 4 & 0xD0) ^ (data[3] << 4 & 0x70));
        data[3] = (byte)((temp & 0xBE) ^ (data[3] & 0xEB) ^ (temp >> 4 & 0x07) ^ (data[3] >> 4 & 0x0D) ^ (temp << 4 & 0x70) ^ (data[3] << 4 & 0xD0));
        
        // M2
        temp = data[4];
        data[4] = (byte)((temp & 0xEB) ^ (data[5] & 0xBE) ^ (temp >> 4 & 0x0D) ^ (data[5] >> 4 & 0x07) ^ (temp << 4 & 0xD0) ^ (data[5] << 4 & 0x70));
        data[5] = (byte)((temp & 0xBE) ^ (data[5] & 0xEB) ^ (temp >> 4 & 0x07) ^ (data[5] >> 4 & 0x0D) ^ (temp << 4 & 0x70) ^ (data[5] << 4 & 0xD0));
        
        // M3
        temp = data[6];
        data[6] = (byte)((temp & 0xD7) ^ (data[7] & 0x7D) ^ (temp >> 4 & 0x0B) ^ (data[7] >> 4 & 0x0E) ^ (temp << 4 & 0xB0) ^ (data[7] << 4 & 0xE0));
        data[7] = (byte)((temp & 0x7D) ^ (data[7] & 0xD7) ^ (temp >> 4 & 0x0E) ^ (data[7] >> 4 & 0x0B) ^ (temp << 4 & 0xE0) ^ (data[7] << 4 & 0xB0));
        
        return data;
    }


    private byte[] MLayer(byte[] datablock)
    {
        datablock = MPrimeLayer(datablock);
        datablock = ShiftRows(datablock);
        // PrintByteArray(datablock);
        return datablock;
    }

    private byte[] InvMLayer(byte[] datablock)
    {
        datablock = InvShiftRows(datablock);
        datablock = MPrimeLayer(datablock);
        // PrintByteArray(datablock);
        return datablock;
    }

    private byte[] AddRoundConstant(int round, byte[] data)
    {
        for (int i = 0; i < 8; i++)
        {
            data[i] = (byte)(data[i] ^ RC[8 * round + i]);
        }
        // PrintByteArray(data);
        return data;
    }

    private byte[] AddKey(byte[] extendedKey, byte[] data)
    {
        for (int i = 0; i < 8; i++)
        {
            data[i] ^= extendedKey[i + 16];
        }
        // PrintByteArray(data);

        return data;
    }

    public byte[] Decipher(byte[] extendedKey, byte[] datablock)
    {
        byte[] newExtendedKey = (byte[])extendedKey.Clone();

        for (int i = 0; i < 8; i++)
        {
            newExtendedKey[i] = extendedKey[i + 8];
            newExtendedKey[i + 8] = extendedKey[i];
            newExtendedKey[i + 16] ^= RC[i + 88];
        }

        datablock = Cipher(newExtendedKey, datablock);
        return datablock;
    }

    public byte[] Encrypt(byte[] key, byte[] data)
    {
        byte[] extendedKey = ExtendKey(key);
        byte[] result = Cipher(extendedKey, data);
        return result;
    }

    public byte[] Decrypt(byte[] key, byte[] datablock)
    {
        byte[] extendedKey = ExtendKey(key);
        byte[] result = Decipher(extendedKey, datablock);
        return result;
    }

    public void PrintByteArray(byte[] bytes)
    {
        var sb = new StringBuilder("[ ");
        foreach (var b in bytes)
        {
            sb.Append(b + ", ");
        }
        sb.Append("]");
        Console.WriteLine(sb.ToString());
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

            byte[] encryptedBlock = Encrypt(key, block);
            AddStep("Şifrelenmiş blok", BitConverter.ToString(encryptedBlock));
            ciphertext.AddRange(encryptedBlock);
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

            byte[] decryptedBlock = Decrypt(key, block);
            plaintextBytes.AddRange(decryptedBlock);
        }

        return Encoding.UTF8.GetString(plaintextBytes.ToArray());
    }
}
