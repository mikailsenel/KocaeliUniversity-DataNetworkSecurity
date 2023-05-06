using Algorithms.Common.Abstract;
using Algorithms.Common.DataTransferObjects;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Text;

/*Algoritma tamamlanmıştır. Algoritmanın Deşifreleme Adımı Yoktur*/
namespace Algorithms
{
    public class Piccolo : EncryptionAlgorithm
    {
<<<<<<< HEAD
<<<<<<< HEAD
   public void Initial(string input)
{
    byte[] key = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
    byte[] plaintext = new byte[] { 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    Console.WriteLine("Şifrelenecek Metin: " + BitConverter.ToString(plaintext).Replace("-", ""));
    Console.WriteLine("Şifrelenecek Metin binary gösterimi: " + GetBinaryString(plaintext));
    // Düz metnin her baytına S-box uygula
    byte[] sBoxOutput = new byte[8];
    for (int i = 0; i < 8; i++)
    {
        sBoxOutput[i] = sBox[plaintext[i] % 16];
    }
    Console.WriteLine("S-box Çıktısı: " + BitConverter.ToString(sBoxOutput).Replace("-", ""));
    Console.WriteLine("S-box Çıktısı binary gösterimi: " + GetBinaryString(sBoxOutput));
    

    // P-box'ı düz metne uygula
    byte[] pBoxOutput = ApplyPBox(plaintext);
    Console.WriteLine("P-box Çktısı: " + BitConverter.ToString(pBoxOutput).Replace("-", ""));
    Console.WriteLine("P-box Çıktısı binary gösterimi: " + GetBinaryString(pBoxOutput));

    // Round key üret
    byte[][] roundKeys = GenerateRoundKeys(key);

    // 31 tur şifreleme gerçekleştir
    byte[] state = (byte[])pBoxOutput.Clone();
    for (int i = 0; i < 31; i++)
    {
        // Round key'i durum dönüşümü için XOR'la
        state = Xor(state, roundKeys[i]);

        // Durumun her baytına S-box uygula
        for (int j = 0; j < 8; j++)
=======
        public Piccolo(string text) : base(text)
>>>>>>> 538c252effd4caed75e69343b417da63bf31744c
=======
        public Piccolo(string text) : base(text)
>>>>>>> 538c252 (Call of algorithms over dashboard.)
        {

        }

        protected override void Initial(string input)
        {
            byte[] key = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
            byte[] plaintext = new byte[] { 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
            Console.WriteLine("Şifrelenecek Metin: " + BitConverter.ToString(plaintext).Replace("-", ""));
            AddStep("Şifrelenecek Metin: ", BitConverter.ToString(plaintext).Replace("-", ""));
            // Düz metnin her baytına S-box uygula
            byte[] sBoxOutput = new byte[8];
            for (int i = 0; i < 8; i++)
            {
                sBoxOutput[i] = sBox[plaintext[i] % 16];
            }
            AddStep("S-box Çıktısı: " , BitConverter.ToString(sBoxOutput).Replace("-", ""));
            Console.WriteLine("S-box Çıktısı: " + BitConverter.ToString(sBoxOutput).Replace("-", ""));

<<<<<<< HEAD
<<<<<<< HEAD
    Console.WriteLine("Şifrelenmiş Metin: " + BitConverter.ToString(state).Replace("-", ""));
    Console.WriteLine("Şifrelenmiş Metin Çıktısı binary gösterimi: " + GetBinaryString(state));
=======
=======
>>>>>>> 538c252 (Call of algorithms over dashboard.)
            // P-box'ı düz metne uygula
            byte[] pBoxOutput = ApplyPBox(plaintext);
            AddStep("P-box Çktısı: " , BitConverter.ToString(pBoxOutput).Replace("-", ""));
            Console.WriteLine("P-box Çktısı: " + BitConverter.ToString(pBoxOutput).Replace("-", ""));
<<<<<<< HEAD
>>>>>>> 538c252effd4caed75e69343b417da63bf31744c
=======
>>>>>>> 538c252 (Call of algorithms over dashboard.)

            // Round key üret
            byte[][] roundKeys = GenerateRoundKeys(key);

            // 31 tur şifreleme gerçekleştir
            byte[] state = (byte[])pBoxOutput.Clone();
            for (int i = 0; i < 31; i++)
            {
                // Round key'i durum dönüşümü için XOR'la
                state = Xor(state, roundKeys[i]);

                // Durumun her baytına S-box uygula
                for (int j = 0; j < 8; j++)
                {
                    state[j] = sBox[state[j] % 16];
                }

                // P-box'ı duruma uygula
                state = ApplyPBox(state);
            }

            AddStep("Şifrelenmiş Metin: " , BitConverter.ToString(state).Replace("-", ""));

        }// Substitution kutusu (S-box)  Piccolo şifreleme algoritması için
        private  readonly byte[] sBox = {
    0x6, 0x4, 0xc, 0x5, 0x0, 0x7, 0x2, 0xe, 0x1, 0xf, 0x3, 0xd, 0x8, 0xa, 0x9, 0xb
};

        // Permutasyon kutusu (P-box) Piccolo şifreleme algoritması için
        private  readonly byte[] pBox = {
    0x0, 0x4, 0x8, 0xc, 0x1, 0x5, 0x9, 0xd, 0x2, 0x6, 0xa, 0xe, 0x3, 0x7, 0xb, 0xf
};


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



<<<<<<< HEAD
<<<<<<< HEAD
    Console.WriteLine("Şifrelenmiş key'in çıktısı: " + BitConverter.ToString(state));
  
    return state;
}

    //  Round keys üretimi  Piccolo şifreleme algoritması için
    private static byte[][] GenerateRoundKeys(byte[] key)
{
    byte[][] roundKeys = new byte[31][];

    //  round key'in key ile başlatılması
    roundKeys[0] = key;

    //  31 adet round keys üretilmesi
    for (int i = 1; i < 31; i++)
    {
        //  61 bit sola kaydır
        byte[] rotatedKey = RotateLeft(key, 61);

        //  S-box uygulaması her bir  key'den byte  üretimi
        for (int j = 0; j < 8; j++)
=======
        // Piccolo şifreleme fonksiyonu
        public  byte[] Encrypt(byte[] key, byte[] plaintext)
>>>>>>> 538c252effd4caed75e69343b417da63bf31744c
=======
        // Piccolo şifreleme fonksiyonu
        public  byte[] Encrypt(byte[] key, byte[] plaintext)
>>>>>>> 538c252 (Call of algorithms over dashboard.)
        {
            if (key == null || key.Length != 8)
                throw new ArgumentException("Geçersiz key boyutu:  8 byte olmalı");
            if (plaintext == null || plaintext.Length != 8)
                throw new ArgumentException("Geçersiz  metin boyutu: 8 byte olmalı");

            byte[] state = (byte[])plaintext.Clone();

            // round key üret
            byte[][] roundKeys = GenerateRoundKeys(key);

            // PŞifreleme için 31 dönüşümlü adımı uygulama
            for (int i = 0; i < 31; i++)
            {
                //  S-Box'ı her bir byte durumu için uygula
                for (int j = 0; j < 8; j++)
                {
                    state[j] = sBox[state[j] % 16];
                }

                //  P-box'ı duruma uygula
                state = ApplyPBox(state);

                // Round key ile XOR'la
                state = Xor(state, roundKeys[i]);
            }

            AddStep("Şifrelenmiş key'in çıktısı: " , BitConverter.ToString(state));
            Console.WriteLine("Şifrelenmiş key'in çıktısı: " + BitConverter.ToString(state));
            return state;
        }

        //  Round keys üretimi  Piccolo şifreleme algoritması için
        private  byte[][] GenerateRoundKeys(byte[] key)
        {
            byte[][] roundKeys = new byte[31][];

            //  round key'in key ile başlatılması
            roundKeys[0] = key;

            //  31 adet round keys üretilmesi
            for (int i = 1; i < 31; i++)
            {
                //  61 bit sola kaydır
                byte[] rotatedKey = RotateLeft(key, 61);

                //  S-box uygulaması her bir  key'den byte  üretimi
                for (int j = 0; j < 8; j++)
                {
                    rotatedKey[j] = sBox[rotatedKey[j] % 16];
                }

                // Anahtarın ilk baytı ile yuvarlak sabiti XOR'lama
                byte roundConstant = (byte)(i & 0x1f);
                rotatedKey[0] ^= roundConstant;

                //  Döndürülen key önceki round key'i XOR'la
                roundKeys[i] = Xor(rotatedKey, roundKeys[i - 1]);

                //Key'i önceki round keye ayarla
                key = roundKeys[i - 1];
            }
            return roundKeys;
        }




        // XOR two byte arrays of equal length
        private  byte[] Xor(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length)
                throw new ArgumentException("Invalid argument: arrays must be of equal length");

            byte[] result = new byte[a.Length];

            for (int i = 0; i < a.Length; i++)
            {
                result[i] = (byte)(a[i] ^ b[i]);
            }

            return result;
        }

        // Rotate a byte array left by a given number of bits
        private  byte[] RotateLeft(byte[] input, int bits)
        {
            byte[] output = new byte[input.Length];
            int bytes = bits / 8;
            int shift = bits % 8;

<<<<<<< HEAD
<<<<<<< HEAD
        return output;
    }

        public static string GetBinaryString(byte[] data)
{
    StringBuilder binaryString = new StringBuilder();
    foreach (byte b in data)
    {
        string binary = Convert.ToString(b, 2).PadLeft(8, '0');
        binaryString.Append(binary);
    }
    return binaryString.ToString();
}
}
=======
=======
>>>>>>> 538c252 (Call of algorithms over dashboard.)
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
<<<<<<< HEAD
>>>>>>> 538c252effd4caed75e69343b417da63bf31744c
=======
>>>>>>> 538c252 (Call of algorithms over dashboard.)

    }

}
