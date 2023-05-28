using Algorithms.Common.Abstract;

using System;
using System.Text;
using Algorithms.Common.Enums;
using Algorithms.Common.DataTransferObjects;

namespace Algorithms;

// ----------------------------------------------------------------
// TAMAMLANDI
// ----------------------------------------------------------------

public class Robin : EncryptionAlgorithm
{
    public Robin(InputDto inputDto) : base(inputDto)
    {

    }

    protected override void Initial(string inputKey, DataTypes inputTypes, DataTypes outputTypes)
    {
        if (inputKey.Length != 16)
        {
            throw new ArgumentException("Key uzunluğu (16 byte, 128 bit) olmalı.");
        }
        byte[] key = Encoding.ASCII.GetBytes(inputKey);

        // Console.WriteLine(BitConverter.ToString(PLAIN));
        // byte[] encrypted = this.Encrypt(PLAIN, KEY);
        // Console.WriteLine(BitConverter.ToString(encrypted));
        // byte[] decrypted = this.Decrypt(encrypted, KEY);
        // Console.WriteLine(BitConverter.ToString(decrypted));

        string plaintext = StringValue;
        AddStep( "Şifrelenecek metin", plaintext);
        Console.WriteLine(plaintext);
        
        byte[] ciphertext = this.EncryptString(key, plaintext);
        AddStep( "Şifrelenmiş metin", BitConverter.ToString(ciphertext));
        Console.WriteLine(BitConverter.ToString(ciphertext));
    
        string descryptedtext = this.DecryptString(key, ciphertext);
        Console.WriteLine(descryptedtext);
        AddStep( "Şifrelenecek girdi:", descryptedtext);

        FinalStep(descryptedtext, DataTypes.String, outputTypes);
    }


    int STATE_SIZE = 128;
    int CONST_NUM = 16;

    private void Class13(ref ushort A, ref ushort B, ref ushort C, ref ushort D, ref ushort X, ref ushort Y, ref ushort Z, ref ushort T)
    {
        ushort __a, __b, __c, __d;
        __a = (ushort)(A & B);
        __a ^= C;
        __c = (ushort)(B | C);
        __c ^= D;
        __d = (ushort)(__a & D);
        __d ^= A;
        __b = (ushort)(__c & A);
        __b ^= B;
        X ^= __a;
        Y ^= __b;
        Z ^= __c;
        T ^= __d;
    }

    private void SBOX(ushort[] x)
    {
        Class13(ref x[4], ref x[5], ref x[6], ref x[7], ref x[0], ref x[1], ref x[2], ref x[3]);
        Class13(ref x[0], ref x[1], ref x[2], ref x[3], ref x[4], ref x[5], ref x[6], ref x[7]);
        Class13(ref x[4], ref x[5], ref x[6], ref x[7], ref x[0], ref x[1], ref x[2], ref x[3]);
    }


    ushort[] LBox1 = new ushort[256] {
        0x0000, 0xfffe, 0xccc1, 0x333f, 0xaaa1, 0x555f, 0x6660, 0x999e,
        0x9991, 0x666f, 0x5550, 0xaaae, 0x3330, 0xccce, 0xfff1, 0x000f,
        0x6689, 0x9977, 0xaa48, 0x55b6, 0xcc28, 0x33d6, 0x00e9, 0xff17,
        0xff18, 0x00e6, 0x33d9, 0xcc27, 0x55b9, 0xaa47, 0x9978, 0x6686,
        0x5585, 0xaa7b, 0x9944, 0x66ba, 0xff24, 0x00da, 0x33e5, 0xcc1b,
        0xcc14, 0x33ea, 0x00d5, 0xff2b, 0x66b5, 0x994b, 0xaa74, 0x558a,
        0x330c, 0xccf2, 0xffcd, 0x0033, 0x99ad, 0x6653, 0x556c, 0xaa92,
        0xaa9d, 0x5563, 0x665c, 0x99a2, 0x003c, 0xffc2, 0xccfd, 0x3303,
        0x3383, 0xcc7d, 0xff42, 0x00bc, 0x9922, 0x66dc, 0x55e3, 0xaa1d,
        0xaa12, 0x55ec, 0x66d3, 0x992d, 0x00b3, 0xff4d, 0xcc72, 0x338c,
        0x550a, 0xaaf4, 0x99cb, 0x6635, 0xffab, 0x0055, 0x336a, 0xcc94,
        0xcc9b, 0x3365, 0x005a, 0xffa4, 0x663a, 0x99c4, 0xaafb, 0x5505,
        0x6606, 0x99f8, 0xaac7, 0x5539, 0xcca7, 0x3359, 0x0066, 0xff98,
        0xff97, 0x0069, 0x3356, 0xcca8, 0x5536, 0xaac8, 0x99f7, 0x6609,
        0x008f, 0xff71, 0xcc4e, 0x33b0, 0xaa2e, 0x55d0, 0x66ef, 0x9911,
        0x991e, 0x66e0, 0x55df, 0xaa21, 0x33bf, 0xcc41, 0xff7e, 0x0080,
        0x007f, 0xff81, 0xccbe, 0x3340, 0xaade, 0x5520, 0x661f, 0x99e1,
        0x99ee, 0x6610, 0x552f, 0xaad1, 0x334f, 0xccb1, 0xff8e, 0x0070,
        0x66f6, 0x9908, 0xaa37, 0x55c9, 0xcc57, 0x33a9, 0x0096, 0xff68,
        0xff67, 0x0099, 0x33a6, 0xcc58, 0x55c6, 0xaa38, 0x9907, 0x66f9,
        0x55fa, 0xaa04, 0x993b, 0x66c5, 0xff5b, 0x00a5, 0x339a, 0xcc64,
        0xcc6b, 0x3395, 0x00aa, 0xff54, 0x66ca, 0x9934, 0xaa0b, 0x55f5,
        0x3373, 0xcc8d, 0xffb2, 0x004c, 0x99d2, 0x662c, 0x5513, 0xaaed,
        0xaae2, 0x551c, 0x6623, 0x99dd, 0x0043, 0xffbd, 0xcc82, 0x337c,
        0x33fc, 0xcc02, 0xff3d, 0x00c3, 0x995d, 0x66a3, 0x559c, 0xaa62,
        0xaa6d, 0x5593, 0x66ac, 0x9952, 0x00cc, 0xff32, 0xcc0d, 0x33f3,
        0x5575, 0xaa8b, 0x99b4, 0x664a, 0xffd4, 0x002a, 0x3315, 0xcceb,
        0xcce4, 0x331a, 0x0025, 0xffdb, 0x6645, 0x99bb, 0xaa84, 0x557a,
        0x6679, 0x9987, 0xaab8, 0x5546, 0xccd8, 0x3326, 0x0019, 0xffe7,
        0xffe8, 0x0016, 0x3329, 0xccd7, 0x5549, 0xaab7, 0x9988, 0x6676,
        0x00f0, 0xff0e, 0xcc31, 0x33cf, 0xaa51, 0x55af, 0x6690, 0x996e,
        0x9961, 0x669f, 0x55a0, 0xaa5e, 0x33c0, 0xcc3e, 0xff01, 0x00ff,
    };



    ushort[] LBox2 = new ushort[256] {
            0x0000, 0xe069, 0xd055, 0x303c, 0xb033, 0x505a, 0x6066, 0x800f,
            0x700f, 0x9066, 0xa05a, 0x4033, 0xc03c, 0x2055, 0x1069, 0xf000,
            0x0e69, 0xee00, 0xde3c, 0x3e55, 0xbe5a, 0x5e33, 0x6e0f, 0x8e66,
            0x7e66, 0x9e0f, 0xae33, 0x4e5a, 0xce55, 0x2e3c, 0x1e00, 0xfe69,
            0x0d55, 0xed3c, 0xdd00, 0x3d69, 0xbd66, 0x5d0f, 0x6d33, 0x8d5a,
            0x7d5a, 0x9d33, 0xad0f, 0x4d66, 0xcd69, 0x2d00, 0x1d3c, 0xfd55,
            0x033c, 0xe355, 0xd369, 0x3300, 0xb30f, 0x5366, 0x635a, 0x8333,
            0x7333, 0x935a, 0xa366, 0x430f, 0xc300, 0x2369, 0x1355, 0xf33c,
            0x0b33, 0xeb5a, 0xdb66, 0x3b0f, 0xbb00, 0x5b69, 0x6b55, 0x8b3c,
            0x7b3c, 0x9b55, 0xab69, 0x4b00, 0xcb0f, 0x2b66, 0x1b5a, 0xfb33,
            0x055a, 0xe533, 0xd50f, 0x3566, 0xb569, 0x5500, 0x653c, 0x8555,
            0x7555, 0x953c, 0xa500, 0x4569, 0xc566, 0x250f, 0x1533, 0xf55a,
            0x0666, 0xe60f, 0xd633, 0x365a, 0xb655, 0x563c, 0x6600, 0x8669,
            0x7669, 0x9600, 0xa63c, 0x4655, 0xc65a, 0x2633, 0x160f, 0xf666,
            0x080f, 0xe866, 0xd85a, 0x3833, 0xb83c, 0x5855, 0x6869, 0x8800,
            0x7800, 0x9869, 0xa855, 0x483c, 0xc833, 0x285a, 0x1866, 0xf80f,
            0x070f, 0xe766, 0xd75a, 0x3733, 0xb73c, 0x5755, 0x6769, 0x8700,
            0x7700, 0x9769, 0xa755, 0x473c, 0xc733, 0x275a, 0x1766, 0xf70f,
            0x0966, 0xe90f, 0xd933, 0x395a, 0xb955, 0x593c, 0x6900, 0x8969,
            0x7969, 0x9900, 0xa93c, 0x4955, 0xc95a, 0x2933, 0x190f, 0xf966,
            0x0a5a, 0xea33, 0xda0f, 0x3a66, 0xba69, 0x5a00, 0x6a3c, 0x8a55,
            0x7a55, 0x9a3c, 0xaa00, 0x4a69, 0xca66, 0x2a0f, 0x1a33, 0xfa5a,
            0x0433, 0xe45a, 0xd466, 0x340f, 0xb400, 0x5469, 0x6455, 0x843c,
            0x743c, 0x9455, 0xa469, 0x4400, 0xc40f, 0x2466, 0x145a, 0xf433,
            0x0c3c, 0xec55, 0xdc69, 0x3c00, 0xbc0f, 0x5c66, 0x6c5a, 0x8c33,
            0x7c33, 0x9c5a, 0xac66, 0x4c0f, 0xcc00, 0x2c69, 0x1c55, 0xfc3c,
            0x0255, 0xe23c, 0xd200, 0x3269, 0xb266, 0x520f, 0x6233, 0x825a,
            0x725a, 0x9233, 0xa20f, 0x4266, 0xc269, 0x2200, 0x123c, 0xf255,
            0x0169, 0xe100, 0xd13c, 0x3155, 0xb15a, 0x5133, 0x610f, 0x8166,
            0x7166, 0x910f, 0xa133, 0x415a, 0xc155, 0x213c, 0x1100, 0xf169,
            0x0f00, 0xef69, 0xdf55, 0x3f3c, 0xbf33, 0x5f5a, 0x6f66, 0x8f0f,
            0x7f0f, 0x9f66, 0xaf5a, 0x4f33, 0xcf3c, 0x2f55, 0x1f69, 0xff00,
    };

    byte[] Encrypt(byte[] input, byte[] key)
    {
        // Access state as 16-bit values
        // Assumes little-endian machine
        ushort[] data = new ushort[8];
        ushort[] k = new ushort[8];

        Buffer.BlockCopy(input, 0, data, 0, 16);
        Buffer.BlockCopy(key, 0, k, 0, 16);

        // Initial key addition
        for (int j = 0; j < 8; j++)
            data[j] ^= k[j];
        AddStep( "Initial key addition", BitConverter.ToString(ushortToBytes(data)));

        for (int i = 0; i < 16; i++)
        {
            // Round constant
            data[0] ^= LBox1[i + 1];

            // SBox layer (bitsliced)
            SBOX(data);
            AddStep( "SBOX Sonrası", BitConverter.ToString(ushortToBytes(data)));

            // LBox layer (tables)
            for (int j = 0; j < 8; j++)
                data[j] = (ushort)(LBox2[data[j] >> 8] ^ LBox1[data[j] & 0xff]);
            AddStep( "LBox layer Sonrası", BitConverter.ToString(ushortToBytes(data)));

            // Key addition
            for (int j = 0; j < 8; j++)
                data[j] ^= k[j];
            AddStep( "Key addition Sonrası", BitConverter.ToString(ushortToBytes(data)));

            /* printf("%2d:\n",i); */
            /* print_state(data); */
        }

        // Free L-box layer inversion
        /* for (int j = 0; j < 8; j++) */
        /*     data[j] = (ushort)(LBox2[data[j] >> 8] ^ LBox1[data[j] & 0xff]); */
        byte[] data2 = new byte[16];
        Buffer.BlockCopy(data, 0, data2, 0, 16);
        return data2;
    }

    byte[] ushortToBytes(ushort[] input){
        byte[] data = new byte[16];
        Buffer.BlockCopy(input, 0, data, 0, 16);
        return data;
    }

    byte[] Decrypt(byte[] input, byte[] key)
    {
        // Access state as 16-bit values
        // Assumes little-endian machine
        ushort[] data = new ushort[8];
        ushort[] k = new ushort[8];

        Buffer.BlockCopy(input, 0, data, 0, 16);
        Buffer.BlockCopy(key, 0, k, 0, 16);

        // Initial key addition
        for (int j = 0; j < 8; j++)
            data[j] ^= k[j];

        for (int i = 0; i < 16; i++)
        {
            // LBox layer (tables)
            for (int j = 0; j < 8; j++)
                data[j] = (ushort)(LBox2[data[j] >> 8] ^ LBox1[data[j] & 0xff]);

            // SBox layer (bitsliced)
            SBOX(data);

            // Key addition
            for (int j = 0; j < 8; j++)
                data[j] ^= k[j];

            // Round constant
            data[0] ^= LBox1[16 - i];
            // Console.WriteLine($"{i}:");
        }

        byte[] data2 = new byte[16];
        Buffer.BlockCopy(data, 0, data2, 0, 16);
        return data2;
    }

    public byte[] EncryptString(byte[] key, string plaintext)
    {
        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        List<byte> ciphertext = new List<byte>();

        int blockSize = 16;
        int totalBlocks = (int)Math.Ceiling((double)plaintextBytes.Length / blockSize);

        for (int blockIndex = 0; blockIndex < totalBlocks; blockIndex++)
        {
            int startIndex = blockIndex * blockSize;
            int endIndex = Math.Min(startIndex + blockSize, plaintextBytes.Length);
            int blockLength = endIndex - startIndex;

            byte[] block = new byte[blockSize];
            Array.Copy(plaintextBytes, startIndex, block, 0, blockLength);

            byte[] encryptedBlock = Encrypt(block, key);
            ciphertext.AddRange(encryptedBlock);
        }

        return ciphertext.ToArray();
    }

    public string DecryptString(byte[] key, byte[] ciphertext)
    {
        List<byte> plaintextBytes = new List<byte>();

        int blockSize = 16;
        int totalBlocks = ciphertext.Length / blockSize;

        for (int blockIndex = 0; blockIndex < totalBlocks; blockIndex++)
        {
            int startIndex = blockIndex * blockSize;
            byte[] block = new byte[blockSize];
            Array.Copy(ciphertext, startIndex, block, 0, blockSize);

            byte[] decryptedBlock = Decrypt(block, key);
            plaintextBytes.AddRange(decryptedBlock);
        }

        return Encoding.UTF8.GetString(plaintextBytes.ToArray());
    }

}
