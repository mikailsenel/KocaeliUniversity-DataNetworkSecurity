using Algorithms.Common.Abstract;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Algorithms
{
    public class Simon : EncryptionAlgorithm

    {

        //Değişken bildirimi y yapıcısı

        private static readonly ulong[] z = { 0b11111010001001010110000111001101111101000100101011000011100110,
                          0b10001110111110010011000010110101000111011111001001100001011010,
                          0b10101111011100000011010010011000101000010001111110010110110011,
                          0b11011011101011000110010111100000010010001010011100110100001111,
                          0b11010001111001101011011000100000010111000011001010010011101111 };


        private int t, j, n, m;
        private ulong[] keysGlobal;

        public Simon(string text) : base(text)
        {

        }

        protected override void Initial(string text, string key)
        {
            // Kullanılacak bloğun veya sözcüğün boyutunu ve anahtarın boyutunu parametrelere göre alan sınıfın yapıcısı,
            // Şifreleyicinin mevcut durumu yalnızca 128 bit bloklarla şifrelemeye izin verir

            int BlockSize = 128;
            int KeySize = 128;
            //Hesaplama n ve m
            n = BlockSize / 2;
            m = KeySize / n;

            // T ve J'yi hesaplarım 
            // Sadece n'nin 64 değerinde olduğu durum uygulanır
            if ((n == 16) && (m == 4)) { j = 0; t = 32; }
            if ((n == 24) && (m == 3)) { j = 0; t = 36; }
            if ((n == 24) && (m == 4)) { j = 1; t = 36; }
            if ((n == 32) && (m == 3)) { j = 2; t = 42; }
            if ((n == 32) && (m == 4)) { j = 3; t = 44; }
            if ((n == 48) && (m == 2)) { j = 2; t = 52; }
            if ((n == 48) && (m == 3)) { j = 3; t = 54; }
            if ((n == 64) && (m == 2)) { j = 2; t = 68; }
            if ((n == 64) && (m == 3)) { j = 3; t = 69; }
            if ((n == 64) && (m == 4)) { j = 4; t = 72; }

            keysGlobal = new ulong[0];

            byte[] bufferPlain = Encoding.ASCII.GetBytes(text);

            byte[] bufferKey = new byte[] {0xDE, 0xAD, 0xBE, 0xEF,
                                     0xCA, 0xFE, 0xBA, 0xBE,
                                     0xFE, 0xED, 0xFA, 0xCE,
                                     0xDE, 0xAF, 0xFA, 0xCE};

            // girdilerin uzunluklarını kontrol et
            if (bufferPlain.Length != BlockSize / 8)
                throw new ArgumentException("Text boyutu " + BlockSize + " bit uzunluğunda olmalı");            


            AddStep("Düz metin: ", BitConverter.ToString(bufferPlain));
            AddStep("Düz metin: ", toBinaryString(bufferPlain));
            //Console.WriteLine("Düz metin: " + BitConverter.ToString(bufferPlain));

            AddStep("Anahtar: ", BitConverter.ToString(bufferKey));
            AddStep("Anahtar: ", toBinaryString(bufferKey));
            //Console.WriteLine("Anahtar: " + BitConverter.ToString(bufferKey));


            byte[] ciphertext = Encrypt(bufferKey, bufferPlain);

            // Şifreli metni ekrana yazdırın
            AddStep("Şifreli metin: ", BitConverter.ToString(ciphertext));
            AddStep("Şifreli metin: ", toBinaryString(ciphertext));
            //Console.WriteLine("Şifreli metin: " + BitConverter.ToString(ciphertext));

            // deşifreleme işlemi 
            byte[] decryptedtext = Decrypt(bufferKey, ciphertext);

            // Çözülmüş düz metni ekrana yazdırın
            AddStep("Çözülmüş metin: ", BitConverter.ToString(decryptedtext));
            AddStep("Çözülmüş metin: ", toBinaryString(decryptedtext));
            //Console.WriteLine("Çözülmüş metin: " + BitConverter.ToString(decryptedtext));

        }



       

        

        //Şifreleme ve şifre çözme işlevleri

        public byte[] Encrypt(byte[] key, byte[] msg)
        {
            ulong[] keyU = byteToUlongs(key, m*(n/8));
            ulong[] msgU = byteToUlongs2(msg);
            ulong[] encrypt = new ulong[msgU.Length];

            for (int i = 0; i < msgU.Length / 2; i++)
            {

                ulong[] cif = EncryptBlock(keyExpansion(keyU), new ulong[] { msgU[i], msgU[i + 1] });
                encrypt[i] = cif[0];
                encrypt[i + 1] = cif[1];

                
            }


            return ulongToByte(encrypt);

        }

        public byte[] Decrypt(byte[] key, byte[] msg)
        {

            ulong[] keyU = byteToUlongs(key, m * (n / 8));
            ulong[] msgU = byteToUlongs2(msg);


            ulong[] descrypt = new ulong[msgU.Length];
            for (int i = 0; i < msgU.Length / 2; i++)
            {
                ulong[] des = DecryptBlock(keyExpansion(keyU), new ulong[] { msgU[i], msgU[i + 1] });
                descrypt[i] = des[0];
                descrypt[i + 1] = des[1];                

            }

            return ulongToByte(descrypt);

        }

        /*
        private ulong[] Encrypt(ulong[] key, ulong[] msg)
        {
            ulong[] encrypt = new ulong[msg.Length];
            for(int i = 0; i< msg.Length/2; i++) { 
                ulong[] cif = EncryptBlock(keyExpansion(key), new ulong[] { msg[i], msg[i + 1] });
                encrypt[i] = cif[0];
                encrypt[i + 1] = cif[1];
            }
            return encrypt;
        }

        private ulong[] Decrypt(ulong[] key, ulong[] msg)
        {
            ulong[] decrypt = new ulong[msg.Length];
            for (int i = 0; i < msg.Length / 2; i++)
            {
                ulong[] cif = DecryptBlock(keyExpansion(key), new ulong[] { msg[i], msg[i + 1] });
                decrypt[i] = cif[0];
                decrypt[i + 1] = cif[1];
            }
            return decrypt;
        }

               

        // Tek blok için blok şifreleme ve şifre çözme işlevleri
        // Bu işlevleri yalnızca "keysGlobal" değişkeni yüklendiğinde kullanın

        public byte[] EncryptBlock(byte[] block)
        {
            ulong[] msg = byteToUlongs2(block);
            for (int i = 0; i < t; i++)
            {
                ulong tmp = msg[1];
                msg[1] = msg[0] ^ (rotl(msg[1], 1) + rotl(msg[1], 8)) ^ rotl(msg[1], 2) ^ keysGlobal[i];
                msg[0] = tmp;
            }
            return ulongToByte(msg);
        }

        public byte[] DecryptBlock(byte[] block)
        {
            ulong[] msg = byteToUlongs2(block);
            for (int i = t - 1; i >= 0; i--)
            {
                ulong tmp = msg[0];
                msg[0] = msg[1] ^ keysGlobal[i] ^ rotl(msg[0], 2) ^ (rotl(msg[0], 1) + rotl(msg[0], 8));
                msg[1] = tmp;
            }
            return ulongToByte(msg);
        }

        */


        // Blok şifre ve şifre çözme fonksiyonları

        private ulong[] EncryptBlock(ulong[] keys, ulong[] msg)
        {
            for (int i=0; i<t; i++)
            {
                ulong tmp = msg[1];
               // Console.WriteLine(BitConverter.ToString(ulongToByte(msg)), msg[1], msg[1]);
                msg[1] = msg[0] ^ (rotl(msg[1], 1) & rotl(msg[1], 8)) ^ rotl(msg[1], 2) ^ keys[i];
                msg[0] = tmp;

                AddStep("Encryption Round : (" + i.ToString() + ") ", toBinaryString(ulongToByte(msg)));
            }
            return msg;
        }

        private ulong[] DecryptBlock(ulong[] keys, ulong[] msg)
        {
            for (int i = t-1; i >= 0; i--)
            {
                ulong tmp = msg[0];
                msg[0] = msg[1] ^ keys[i] ^ rotl(msg[0], 2) ^ (rotl(msg[0], 1) & rotl(msg[0], 8));
                msg[1] = tmp;

                AddStep("Decryption Round : (" + i.ToString() + ") ", toBinaryString(ulongToByte(msg)));
            }
            return msg;
        }

        
        // ANAHTAR GENİŞLETME İŞLEVİ

        private ulong[] keyExpansion(ulong[] key)
        {
            if (key.Length != m)
            {
                ulong[] temp = key;
                key = new ulong[m];
                temp.CopyTo(key, 0);
            }
            ulong[] keys = new ulong[t];
            for (int i = 0; i < m; i++)
            {
                keys[i] = key[i];
            }

            ulong zet = z[j];
            ulong tmp;
            for (int i = m; i < t; i++)
            {
                tmp = rotl(keys[i - 1], 3);
                if (m == 4) tmp = tmp ^ keys[i - 3];
                tmp = tmp ^ rotl(tmp, 1);
                keys[i] = keys[i - m] ^ tmp ^ getNBits(rotl(zet, i - m)) ^ (ulong.MaxValue - 3);
                //keys[i] = key[i];
            }
            return keys;
        }
        public void calculateKeys(byte[] key)
        {
            ulong[] keyU = byteToUlongs(key, m * (n / 8));
            keysGlobal = keyExpansion(keyU);
        }

        
        // ARİTMETİK İŞLEMLER

        //Bit kaydırma döndürme
        private ulong rotl(ulong block, int cant)
        {            
            return ((block << cant) + (block >> (64 - cant)));
        }

        //n Anaktarlarını al
        private ulong getNBits(ulong block)
        {
            return block >> (62 - n);
        }
        

        // DÖNÜŞÜM FONKSİYONLARI

        // 64 baytlık sözcük dizileri (uzun), Dizeler ve bayt dizileri arasındaki dönüşümler

        // Bir dizeyi uzun bir diziye dönüştüren işlev, minimum bayt miktarı da seçilebilir
        // (eğer üzerinde kalırlarsa sıfırlarla doldurulurlar)
        public ulong[] stringToUlongs(String s)
        {
            return stringToUlongs(s, 0);
        }
        public ulong[] stringToUlongs(String s, int minBytes)
        {
            // Dizeyi bir bayt dizisine geçiriyorum
            return byteToUlongs(Encoding.ASCII.GetBytes(s), minBytes);
        }

        // Bir bayt dizisini bir ulong dizisine dönüştüren işlev
        public ulong[] byteToUlongs2(byte[] bytes, int minBytes)
        {

            // Diziyi, oluşturulmuş 16 baytlık (128 baytlık kelime) grupları olan başka bir diziye aktarıyorum   
            int cant = (bytes.Length % 16 == 0) ? bytes.Length : bytes.Length + (16 - bytes.Length % 16);
            if (cant < minBytes) cant = minBytes;
            byte[] b = new byte[cant];
            bytes.CopyTo(b, 0);

            Console.WriteLine();

            //Kelime dizisini oluşturuyorum (8 bayt)
            ulong[] c = new ulong[b.Length / 8];

            // Baytlardan kelimelere geçiş yapıyorum
            for (int i = 0; i < c.Length; i++)
                c[i] = BitConverter.ToUInt64(b, i * 8);

            return c;
        }

        // Fonksiyonun aşırı yüklenmesi
        public ulong[] byteToUlongs2(byte[] bytes)
        {
            return byteToUlongs2(bytes, 0);
        }

        // Bir bayt dizisini bir ulong dizisine dönüştüren işlev
        public ulong[] byteToUlongs(byte[] bytes, int minBytes)
        {

            // Diziyi, 8 baytlık (64 baytlık ulong) grupların oluşturduğu başka bir diziye geçiriyorum   
            int cant = (bytes.Length % 8 == 0) ? bytes.Length : bytes.Length + (8 - bytes.Length % 8);
            if (cant < minBytes) cant = minBytes;
            byte[] b = new byte[cant];
            bytes.CopyTo(b, 0);

            Console.WriteLine();

            //Kelime dizisi oluşturuyorum (8 bytes)
            ulong[] c = new ulong[b.Length / 8];

            // Baytlardan kelimelere geçiş yapıyorum
            for (int i = 0; i < c.Length; i++)
                c[i] = BitConverter.ToUInt64(b, i * 8);

            return c;
        }

        // Fonksiyonun aşırı yüklenmesi
        public ulong[] byteToUlongs(byte[] bytes)
        {
            return byteToUlongs(bytes, 0);
        }


        // Bir diziyi ulong'dan bir dizeye dönüştüren işlev (ASCII cinsinden)
        public String ulongToString(ulong[] array)
        {
            String decoded = "";
            for (int i = 0; i < array.Length; i++)
            {
                decoded += Encoding.ASCII.GetString(BitConverter.GetBytes(array[i]));
            }
            return decoded;
        }

        public byte[] ulongToByte(ulong[] array)
        {
            byte[] bytes = new byte[array.Length * 8];

            for(int i=0; i<array.Length; i++)
            {
                byte[] bytesUlong = BitConverter.GetBytes(array[i]);
                for(int j = 0; j<bytesUlong.Length; j++)
                {
                    bytes[i * 8 + j] = bytesUlong[j];
                }
            }

            return bytes;
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



        


    }
}
