using Algorithms.Common.Abstract;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Algorithms
{
    public class Sea : EncryptionAlgorithm
    {
        // SEA algoritmasının parametreleri 
        const int KEY_LENGTH = 128; // şifreleme anahtarının uzunluğu (bit) 
        const int BLOCK_SIZE = 128; // blok boyutu (bit) 
        const int ROUND_COUNT = 16; // yuvarlama sayısı 

       
        public Sea(string input) : base(input)
        {
        }


        protected override void Initial(string input,string inputKey)
        {
            byte[] plaintext = System.Text.Encoding.UTF8.GetBytes(input);

            byte[] key = new byte[] {0xDE, 0xAD, 0xBE, 0xEF,
                                     0xCA, 0xFE, 0xBA, 0xBE,
                                     0xFE, 0xED, 0xFA, 0xCE,
                                     0xDE, 0xAF, 0xFA, 0xCE};


            // girdilerin uzunluklarını kontrol et 
            if (plaintext.Length != BLOCK_SIZE / 8)
                throw new ArgumentException("Text boyutu " + BLOCK_SIZE + " bit uzunluğunda olmalı");

            if (key.Length != KEY_LENGTH / 8)
                throw new ArgumentException("Key " + KEY_LENGTH + " bit uzunluğunda olmalı");


            AddStep("Düz metin: ", BitConverter.ToString(plaintext));
            AddStep("Düz metin: ", toBinaryString(plaintext));
            //Console.WriteLine("Düz metin: " + BitConverter.ToString(plaintext));

            AddStep("Anahtar: ", BitConverter.ToString(key));
            AddStep("Anahtar: ", toBinaryString(key));
            //Console.WriteLine("Anahtar: " + BitConverter.ToString(key));

            
            byte[] ciphertext = Encrypt(plaintext, key);

            // Şifreli metni ekrana yazdırın
            AddStep("Şifreli metin: ", BitConverter.ToString(ciphertext));
            AddStep("Şifreli metin: ", toBinaryString(ciphertext));
            //Console.WriteLine("Şifreli metin: " + BitConverter.ToString(ciphertext));

            // deşifreleme işlemi 
            byte[] decryptedtext = Decrypt(ciphertext, key);

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
                binaryString.Append(binary+" ");
            }
            return binaryString.ToString();
        }



        // SEA algoritmasının yuvarlama fonksiyonu 
        private UInt64 F(UInt64 x, UInt64 k)
        {
            // x ve k'nın XOR'u 
            UInt64 y = x ^ k;
            // y'nin sağa 8 bit kaydırılması 
            UInt64 z = y >> 8;
            // y ve z'nin XOR'u 
            return y ^ z;
        }
        // SEA algoritmasının şifreleme fonksiyonu 
        private byte[] Encrypt(byte[] plaintext, byte[] key)
        {
            
            // girdileri UInt64 olarak oku 
            UInt64 L = BitConverter.ToUInt64(plaintext, 0); // bloğun sol yarısı 
            UInt64 R = BitConverter.ToUInt64(plaintext, 8); // bloğun sağ yarısı 
            UInt64 K = BitConverter.ToUInt64(key, 0); // anahtar 

            // şifreli metni byte dizisi olarak döndür 
            byte[] ciphertext = new byte[BLOCK_SIZE / 8];

            // yuvarlama işlemleri 
            for (int i = 0; i < ROUND_COUNT; i++)
            {
                // anahtardan türetilen alt anahtar 
                UInt64 Ki = K ^ (UInt64)i;
                // Feistel ağı uygula 
                UInt64 Li = R;
                UInt64 Ri = L ^ F(R, Ki);
                L = Li;
                R = Ri;

                Buffer.BlockCopy(BitConverter.GetBytes(L), 0, ciphertext, 0, 8);
                Buffer.BlockCopy(BitConverter.GetBytes(R), 0, ciphertext, 8, 8);

                AddStep("Encryption Round : (" + i.ToString() + ") ", toBinaryString(ciphertext));
            }

            return ciphertext;
        }

        // SEA algoritmasının deşifreleme fonksiyonu 
        private byte[] Decrypt(byte[] ciphertext, byte[] key)
        {
            // girdilerin uzunluklarını kontrol et 
            if (ciphertext.Length != BLOCK_SIZE / 8)
                throw new ArgumentException("Ciphertext " + BLOCK_SIZE + " bit bit uzunluğunda olmalı");
            if (key.Length != KEY_LENGTH / 8)
                throw new ArgumentException("Key " + KEY_LENGTH  + " bit uzunluğunda olmalı");


            // girdileri UInt64 olarak oku 
            UInt64 L = BitConverter.ToUInt64(ciphertext, 0); // bloğun sol yarısı 
            UInt64 R = BitConverter.ToUInt64(ciphertext, 8); // bloğun sağ yarısı 
            UInt64 K = BitConverter.ToUInt64(key, 0); // anahtar 

            // düz metni byte dizisi olarak döndür 
            byte[] plaintext = new byte[BLOCK_SIZE / 8];

            // yuvarlama işlemleri (ters sırada) 
            for (int i = ROUND_COUNT - 1; i >= 0; i--)
            {
                // anahtardan türetilen alt anahtar 
                UInt64 Ki = K ^ (UInt64)i;
                // Feistel ağı uygula (ters yönde) 
                UInt64 Li = R ^ F(L, Ki);
                UInt64 Ri = L;
                L = Li;
                R = Ri;

                Buffer.BlockCopy(BitConverter.GetBytes(L), 0, plaintext, 0, 8);
                Buffer.BlockCopy(BitConverter.GetBytes(R), 0, plaintext, 8, 8);

                AddStep("Decryption Round : (" + i.ToString() + ") ", toBinaryString(plaintext));
            }

            
            return plaintext;
        }

    }
}
