using Algorithms.Common.Abstract;
using Algorithms.Common.DataTransferObjects;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;


namespace Algorithms;


/*Algoritma tamamlanmıştır.*/
/*

Substitution (Yerine Koyma):
Substitution işlevi, sabit olarak tanımlanmış bir S-box'tan değerleri aratarak girdi baytlarını S-box'tan gelen karşılık gelen değerlerle değiştirerek yerine koyma adımını gerçekleştirir.
permütasyon:
Permütasyon işlevi, sabit bir permütasyon kuralları kümesine dayalı olarak dört adet 32 bitlik kelimenin sırasını karıştırarak permütasyon adımını uygular.

Anahtar Ekleme:
XOR ve Toplama işlevleri, temel toplama adımını uygular. Giriş sözcükleri ile orijinal anahtardan türetilen bir anahtar arasında (sırasıyla) bir XOR işlemi ve bir toplama işlemi gerçekleştirirler.


*/

public class Noekeon: EncryptionAlgorithm
{
    public Noekeon(string text) : base(text)
    {
    }

    protected override void Initial(string input)
    {
        // Ornek input data
        //byte[] inputData = new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, }; //16 bit input data giriş yapılıyor
        byte[] inputData = System.Text.Encoding.UTF8.GetBytes(input);
        AddStep( "Girdi Metin datasi..", BitConverter.ToString(inputData));
        Console.WriteLine("Girdi Metin datasi..: " + BitConverter.ToString(inputData));
        // Ornek key
        uint[] key = new uint[] { 0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210 }; //128 bit data

        // Yerine Koyma Islemi
        byte[] outputData = Substitution(inputData);
        AddStep("Yerine koyma islemi sonrasi data..", BitConverter.ToString(outputData));
        Console.WriteLine("Yerine koyma islemi sonrasi data..: " + BitConverter.ToString(outputData));
        // Permutasyon işlemi
        uint a = BitConverter.ToUInt32(outputData, 0);
        uint b = BitConverter.ToUInt32(outputData, 4);
        uint c = BitConverter.ToUInt32(outputData, 8);
        uint d = BitConverter.ToUInt32(outputData, 12);

        Permutation(ref a, ref b, ref c, ref d);
        outputData = BitConverter.GetBytes(a).Concat(BitConverter.GetBytes(b)).Concat(BitConverter.GetBytes(c)).Concat(BitConverter.GetBytes(d)).ToArray();
        AddStep("Permutasyon sonrasi data..", BitConverter.ToString(outputData));
        Console.WriteLine("Permutasyon sonrasi data..: " + BitConverter.ToString(outputData));
        //  XOR ve Toplama Islemi
        a = BitConverter.ToUInt32(outputData, 0);
        b = BitConverter.ToUInt32(outputData, 4);
        c = BitConverter.ToUInt32(outputData, 8);
        d = BitConverter.ToUInt32(outputData, 12);

        XOR(ref a, ref b, ref c, ref d, key);
        byte[] xordata = BitConverter.GetBytes(a).Concat(BitConverter.GetBytes(b)).Concat(BitConverter.GetBytes(c)).Concat(BitConverter.GetBytes(d)).ToArray();
        AddStep( "Xor sonrasi data..", BitConverter.ToString(xordata));
        Console.WriteLine("Xor sonrasi data..: " + BitConverter.ToString(xordata));

        Addition(ref a, ref b, ref c, ref d, key);
        byte[] addition = BitConverter.GetBytes(a).Concat(BitConverter.GetBytes(b)).Concat(BitConverter.GetBytes(c)).Concat(BitConverter.GetBytes(d)).ToArray();
        AddStep( "Toplama sonrasi data..", BitConverter.ToString(addition));
        Console.WriteLine("Toplama sonrasi data..: " + BitConverter.ToString(addition));
        // Cıktı sonucu

        AddStep( " Sifrelenmiş data..", BitConverter.ToString(outputData));
        Console.WriteLine(" Sifrelenmiş data..: " + BitConverter.ToString(outputData));
    }

    public byte[] Substitution(byte[] input)
    {
        byte[] output = new byte[input.Length];
        byte[] sbox = { // Yerine koyma işlemi arama tablosu 16 * 16 256 bit sbox datası vardır
        0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x0, 0x1, 0x2, 0x3, 0x4,
        0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9,
        0xF, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE,
        0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x0, 0x1, 0x2, 0x3,
        0xE, 0xF, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD,
        0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x0, 0x1, 0x2,
        0xD, 0xE, 0xF, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC,
        0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x0, 0x1,
        0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x0, 0x1, 0x2, 0x3, 0x4,
        0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9,
        0xF, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE,
        0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x0, 0x1, 0x2, 0x3,
        0xE, 0xF, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD,
        0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x0, 0x1, 0x2,
        0xD, 0xE, 0xF, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC,
        0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x0, 0x1
    };
        for (int i = 0; i < input.Length; i++)
        {
            output[i] = sbox[input[i]];
        }
        return output;
    }
    public void Permutation(ref uint a, ref uint b, ref uint c, ref uint d)
    {
        const uint delta = 0x9E3779B9; // Altin oran
        uint tmp;
        for (int i = 0; i < 4; i++)
        {
            // Theta Adimi
            a += c; c ^= b; c = (c << 16) | (c >> 16);
            b += d; d ^= a; d = (d << 12) | (d >> 20);
            a += b; b ^= c; b = (b << 8) | (b >> 24);
            c += d; d ^= a; d = (d << 7) | (d >> 25);

            // Pi adimi
            tmp = a; a = b; b = c; c = d; d = tmp;

            // Gamma adimi
            a = (a << 1) | (a >> 31);
            b = (b << 2) | (b >> 30);
            c = (c << 3) | (c >> 29);
            d = (d << 5) | (d >> 27);

            // Theta adimi
            a += c; c ^= b; c = (c << 16) | (c >> (32 - 16));
            b += d; d ^= a; d = (d << 12) | (d >> 20);
            a += b; b ^= c; b = (b << 8) | (b >> 24);
            c += d; d ^= a; d = (d << 7) | (d >> 25);

            // Key zamanlama
            a ^= delta;
        }

    }

    public void XOR(ref uint a, ref uint b, ref uint c, ref uint d, uint[] key) //xor fonksiyonu
    {
        a ^= key[0];
        b ^= key[1];
        c ^= key[2];
        d ^= key[3];
    }
    public void Addition(ref uint a, ref uint b, ref uint c, ref uint d, uint[] key) //toplama fonksiyonu
    {
        const uint constant = 0x08070605;
        a += constant;
        b += key[0];
        c += key[1];
        d += key[2];
    }

}
