using Algorithms.Common.Abstract;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Algorithms
{
    public class Skinny : EncryptionAlgorithm
    {
        // SKINNY algoritmasının parametreleri
        const int BLOCK_SIZE = 128; // blok boyutu (bit)
        const int KEY_SIZE = 128; // anahtar boyutu (bit)
        const int TWEAK_SIZE = 128; // tweak boyutu (bit)
        const int ROUND_COUNT = 16; // yuvarlama sayısı


        // SKINNY algoritmasının sabit matrisleri
        static byte[,] M0 = new byte[8, 8] {
            {11, 15, 4,20, 31, 41, 121, 11},
            {25, 15,16, 49, 51, 74, 111,21},
            {61, 42, 215, 4, 0, 42, 10, 111},
            {1, 69, 95, 64, 10, 100, 56, 47},
            {87, 88, 98, 90, 44, 42, 2 ,19},
            {1 ,32 ,65 ,19 ,72 ,11 ,88 ,72},
            {95 ,34 ,104 ,62 ,241 ,151 ,162 ,0},
            {92 ,215 ,156 ,114 ,184 ,75 ,94 ,91}
        };

        static byte[,] M00 = new byte[8, 8] {
            {54 ,55 ,41 ,14 ,82 ,12 ,0 ,11},
            {98 ,15 ,132 ,72 ,71 ,10 ,2 ,4},
            {74 ,51 ,64 ,69 ,61 ,122 ,172 ,44},
            {95 ,164 ,61 ,11 ,201 ,12 ,145 ,14},
            {96 ,66 ,64 ,12 ,92 ,60 ,64 ,12},
            {8 ,45 ,58 ,16 ,71 ,61 ,17 ,75},
            {6 ,31 ,10 ,52 ,34 ,43 ,22 ,74},
            {94 ,0 ,72 ,63 ,78 ,88 ,81 ,45}
        };


        // SKINNY algoritmasının S-box tablosu
        static byte[] Sbox = new byte[16] {
            12, 6, 9, 0,
            1, 14, 2, 11,
            4, 5, 3, 15,
            13, 10, 7, 8
        };

        public Skinny(string text) : base(text)
        {
        }

        protected override void Initial(string text)
        {
            // test verileri
            byte[] plaintext = System.Text.Encoding.UTF8.GetBytes(text);
                //new byte[] {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,0x88, 0x99, 0xaa, 0xbb,0xcc, 0xdd, 0xee, 0xff};

            byte[] key = new byte[] {0x00, 0x0a, 0xb2, 0xc3,
                             0x14, 0xba, 0xaa, 0x71,
                             0xe8, 0xa9, 0xa0, 0xba,
                             0x0c, 0xed, 0x07, 0x0f};


            // girdilerin uzunluklarını kontrol et
            if (plaintext.Length != BLOCK_SIZE / 8)
                throw new ArgumentException("Text boyutu " + BLOCK_SIZE + " bit uzunluğunda olmalı");
            if (key.Length != KEY_SIZE / 8)
                throw new ArgumentException("Key " + KEY_SIZE + " bit uzunluğunda olmalı");


            // rastgele bir tweak girdisi oluştur
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] tweak = new byte[TWEAK_SIZE / 8];
            rng.GetBytes(tweak);

            AddStep("Düz metin: ", BitConverter.ToString(plaintext));
            AddStep("Düz metin: " , toBinaryString(plaintext));
            //Console.WriteLine("Düz metin: " + BitConverter.ToString(plaintext));
            //Console.WriteLine("Düz metin: " + toBinaryString(plaintext));


            AddStep("Anahtar: ", BitConverter.ToString(key));
            AddStep("Anahtar: ", toBinaryString(key));

            //Console.WriteLine("Anahtar: " + BitConverter.ToString(key));

            AddStep("Tweak: ", BitConverter.ToString(tweak));
            AddStep("Tweak: ", toBinaryString(tweak));
            //Console.WriteLine("     Tweak: " + BitConverter.ToString(tweak));

            byte[] ciphertext = Encrypt(plaintext, key, tweak);

            // Şifreli metni ekrana yazdırın
            AddStep("Şifreli metin: ", BitConverter.ToString(ciphertext));
            AddStep("Şifreli metin: ", toBinaryString(ciphertext));
            //Console.WriteLine("Şifreli metin: " + BitConverter.ToString(ciphertext));

            // deşifreleme işlemi 
            byte[] decryptedtext = Decrypt(ciphertext, key, tweak);

            // Çözülmüş düz metni ekrana yazdırın
            AddStep("Çözülmüş metin: ", BitConverter.ToString(decryptedtext));
            AddStep("Çözülmüş metin: ", toBinaryString(decryptedtext));
            //Console.WriteLine("Çözülmüş metin: " + BitConverter.ToString(decryptedtext));

        }

        public string toBinaryString(byte[] data)
        {
            StringBuilder binaryString = new StringBuilder();
            foreach (byte r in data)
            {
                string binary = Convert.ToString(r, 2).PadLeft(8, '0');
                binaryString.Append(binary + " ");
            }
            return binaryString.ToString();
        }

        // Bir UInt64 sayısını bir 8x8 byte matrisi ile çarpan fonksiyon
        private UInt64 Multiply(UInt64 x, byte[,] M)
        {
            // sonucu tutacak değişken
            UInt64 y = 0;
            // x'in bitlerini sağdan sola doğru işle
            for (int i = 0; i < 8; i++)
            {
                // x'in i. bitini al
                UInt64 xi = (x >> i) & 1;
                // xi ile M matrisinin i. sütununu XOR'la
                UInt64 yi = 0;
                for (int j = 0; j < 8; j++)
                {
                    // M matrisinin j. satırının i. elemanını al
                    byte Mji = M[j, i];
                    // yi'nin j. bitini Mji ile XOR'la
                    yi ^= (UInt64)Mji << (j * 8);
                }
                // yi'yi xi ile çarp ve y'ye ekle
                y ^= yi * xi;
            }
            // sonucu döndür
            return y;
        }

        // Bir UInt64 sayısının her 4 bitlik parçasını S-box tablosu ile değiştiren fonksiyon
        private UInt64 SubBytes(UInt64 x)
        {
            // sonucu tutacak değişken
            UInt64 y = 0;
            // x'in 4 bitlik parçalarını işle
            for (int i = 0; i < 16; i++)
            {
                // x'in i. parçasını al
                byte xi = (byte)((x >> (i * 4)) & 0xF);
                // xi'yi S-box tablosunda bulunan değerle değiştir
                byte yi = Sbox[xi];
                // yi'yi y'nin i. parçası yap
                y |= (UInt64)yi << (i * 4);
            }
            // sonucu döndür
            return y;
        }

        // SKINNY algoritmasının yuvarlama fonksiyonu
        private UInt64 F(UInt64 x, UInt64 K, UInt64 T)
        {
            // x'i dört farklı işlemden geçir
            // Birinci işlem: x'i M matrisi ile çarp
            UInt64 y = Multiply(x, M0);
            // İkinci işlem: x'i S-box tablosu ile değiştir
            UInt64 z = SubBytes(y);
            // Üçüncü işlem: z'yi M matrisinin tersi ile çarp
            UInt64 w = Multiply(z, M00);
            // Dördüncü işlem: w'yi alt anahtar ve alt tweak ile XOR'la
            UInt64 v = w ^ K ^ T;
            // Sonucu döndür
            return v;
        }

        // SKINNY algoritmasının şifreleme fonksiyonu
        private byte[] Encrypt(byte[] plaintext, byte[] key, byte[] tweak)
        {

            // girdileri UInt64 olarak oku
            UInt64 L = BitConverter.ToUInt64(plaintext, 0); // bloğun sol yarısı
            UInt64 R = BitConverter.ToUInt64(plaintext, 8); // bloğun sağ yarısı
            UInt64 K = BitConverter.ToUInt64(key, 0); // anahtar            
            UInt64 T = BitConverter.ToUInt64(tweak, 0); // tweak girdisi

            // şifreli metni byte dizisi olarak döndür
            byte[] ciphertext = new byte[BLOCK_SIZE / 8];

            // yuvarlama işlemleri
            for (int i = 0; i < ROUND_COUNT; i++)
            {
                // anahtardan ve tweak girdisinden türetilen alt anahtar ve alt tweak
                UInt64 Ki = K ^ (UInt64)i;
                UInt64 Ti = T ^ (UInt64)i;
                // Feistel ağı uygula
                UInt64 Li = R;
                UInt64 Ri = L ^ F(R, Ki, Ti);
                L = Li;
                R = Ri;

                Buffer.BlockCopy(BitConverter.GetBytes(L), 0, ciphertext, 0, 8);
                Buffer.BlockCopy(BitConverter.GetBytes(R), 0, ciphertext, 8, 8);
                AddStep("Encryption Round : (" + i.ToString() + ") ", toBinaryString(ciphertext));                
            }

            //Buffer.BlockCopy(BitConverter.GetBytes(L), 0, ciphertext, 0, 8);
            //Buffer.BlockCopy(BitConverter.GetBytes(R), 0, ciphertext, 8, 8);
            return ciphertext;
        }

        // SKINNY algoritmasının deşifreleme fonksiyonu
        private byte[] Decrypt(byte[] ciphertext, byte[] key, byte[] tweak)
        {
            // girdilerin uzunluklarını kontrol et
            if (ciphertext.Length != BLOCK_SIZE / 8)
                throw new ArgumentException("Ciphertext " + BLOCK_SIZE + " bit bit uzunluğunda olmalı");
            if (key.Length != KEY_SIZE / 8)
                throw new ArgumentException("Key " + KEY_SIZE + " bit uzunluğunda olmalı");
            if (tweak.Length != TWEAK_SIZE / 8)
                throw new ArgumentException("Tweak " + TWEAK_SIZE + " bit uzunluğunda olmalı");

            // girdileri UInt64 olarak oku
            UInt64 L = BitConverter.ToUInt64(ciphertext, 0); // bloğun sol yarısı
            UInt64 R = BitConverter.ToUInt64(ciphertext, 8); // bloğun sağ yarısı
            UInt64 K = BitConverter.ToUInt64(key, 0); // anahtar
            UInt64 T = BitConverter.ToUInt64(tweak, 0); // tweak girdisi

            // düz metni byte dizisi olarak döndür
            byte[] plaintext = new byte[BLOCK_SIZE / 8];

            // yuvarlama işlemleri (ters sırada)
            for (int i = ROUND_COUNT - 1; i >= 0; i--)
            {
                // anahtardan ve tweak girdisinden türetilen alt anahtar ve alt tweak
                UInt64 Ki = K ^ (UInt64)i;
                UInt64 Ti = T ^ (UInt64)i;
                // Feistel ağı uygula (ters yönde)
                UInt64 Li = R ^ F(L, Ki, Ti);
                UInt64 Ri = L;
                L = Li;
                R = Ri;

                Buffer.BlockCopy(BitConverter.GetBytes(L), 0, plaintext, 0, 8);
                Buffer.BlockCopy(BitConverter.GetBytes(R), 0, plaintext, 8, 8);
                AddStep("Decryption Round : (" + i.ToString() + ") ", toBinaryString(plaintext));
                //Console.WriteLine("DEC " + i.ToString() + (i < 10 ? " " : "") + ":" + BitConverter.ToString(plaintext));
            }


            //Buffer.BlockCopy(BitConverter.GetBytes(L), 0, plaintext, 0, 8);
            //Buffer.BlockCopy(BitConverter.GetBytes(R), 0, plaintext, 8, 8);
            return plaintext;
        }




    }
}
