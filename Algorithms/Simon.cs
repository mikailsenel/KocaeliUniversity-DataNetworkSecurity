using Algorithms.Common.Abstract;
using Algorithms.Common.DataTransferObjects;
using Algorithms.Common.Enums;
using System.Text;

namespace Algorithms
{
    public class Simon : EncryptionAlgorithm

    {
        private const int BLOCKSIZE = 128; //bit
        private const int KEYSIZE = 128; //bit
        private const int WORDSIZE = 16; //byte

        private static readonly ulong[] z = { 0b11111010001001010110000111001101111101000100101011000011100110,
                          0b10001110111110010011000010110101000111011111001001100001011010,
                          0b10101111011100000011010010011000101000010001111110010110110011,
                          0b11011011101011000110010111100000010010001010011100110100001111,
                          0b11010001111001101011011000100000010111000011001010010011101111 };

        private int t, j, n, m;

        public Simon(InputDto input) : base(input)
        {
        }

        protected override void Initial(string inputKey, DataTypes inputTypes, DataTypes outputTypes)
        {

            // 128 bit bloklarla şifrelemeye izin verir

            //Hesaplama n ve m
            n = BLOCKSIZE / 2;
            m = KEYSIZE / n;
            j = 2;
            t = 68;


            byte[] plainText = ByteValue;

            string keyHexString = inputKey;
            // Anahtar uzunluğu 16 byte (128 bit) 
            if (keyHexString.Length != (KEYSIZE / 8) * 2) // Her bir byte 2 hexadecimal karakterle temsil edilir
            {
                throw new ArgumentException("Geçersiz anahtar uzunluğu. Anahtar 128 bit (16 byte) olmalıdır.");
            }

            byte[] key = Enumerable.Range(0, keyHexString.Length / 2)
                          .Select(x => Convert.ToByte(keyHexString.Substring(x * 2, 2), 16))
                          .ToArray();


            byte[] chiperText = new byte[plainText.Length % WORDSIZE == 0 ? plainText.Length : plainText.Length + (WORDSIZE - (plainText.Length % WORDSIZE))];

            plainText.CopyTo(chiperText, 0);

            for (int i = 0; i < (chiperText.Length / WORDSIZE); i++)
            {
                byte[] tmp = new byte[WORDSIZE];
                Array.Copy(chiperText, i * WORDSIZE, tmp, 0, WORDSIZE);
                tmp = Encrypt(i + 1, tmp, key);
                Array.Copy(tmp, 0, chiperText, i * WORDSIZE, WORDSIZE);
            }

            byte[] encrytpText = new byte[chiperText.Length];

            chiperText.CopyTo(encrytpText, 0);

            for (int i = 0; i < (chiperText.Length / WORDSIZE); i++)
            {
                byte[] tmp = new byte[WORDSIZE];
                Array.Copy(chiperText, i * WORDSIZE, tmp, 0, WORDSIZE);
                tmp = Decrypt(i + 1, tmp, key);
                Array.Copy(tmp, 0, chiperText, i * WORDSIZE, WORDSIZE);

            }

            clearlast0(ref chiperText);

            AddStep("Düz metin      : " + BitConverter.ToString(plainText), toBinaryString(plainText));

            AddStep("Anahtar        : " + BitConverter.ToString(key), toBinaryString(key));

            AddStep("Şifreli metin  : " + BitConverter.ToString(encrytpText), toBinaryString(encrytpText));

            AddStep("Çözülmüş metin : " + BitConverter.ToString(chiperText), toBinaryString(chiperText));

            FinalStep(chiperText, outputTypes);
        }

        private static string print_chipers(byte[] state, byte[] keyCells)
        {
            return "S = " + BitConverter.ToString(state.Cast<byte>().ToArray()) + (keyCells == null ? "" : " - TK = " + BitConverter.ToString(keyCells.Cast<byte>().ToArray()));
        }

        public static void clearlast0(ref Byte[] chiperText)
        {
            if (chiperText.Length == 0)
                return;

            int clearcount = 0;

            for (int i = (chiperText.Length - 1); i >= (chiperText.Length - WORDSIZE); i--)
            {
                if (chiperText[i] == 0x00)
                    clearcount++;
                else
                    break;
            }

            if (clearcount > 0)
                Array.Resize<Byte>(ref chiperText, chiperText.Length - clearcount);
        }




        //Şifreleme ve şifre çözme işlevleri

        public byte[] Encrypt(int partno, byte[] msg, byte[] key)
        {
            ulong[] keyU = byteToUlongArray(key);
            ulong[] msgU = byteToUlongArray(msg);
            ulong[] encrypt = new ulong[msgU.Length];

            for (int i = 0; i < msgU.Length / 2; i++)
            {

                AddStep("Encryption Part (" + partno.ToString() + ") - Başlangıç : " + print_chipers(ulongToByte(msgU), null), toBinaryString(ulongToByte(msgU)));
                ulong[] keys = keyExpand(keyU);

                for (int it = 0; it < t; it++)
                {
                    ulong tmp = msgU[1];

                    msgU[1] = msgU[0] ^ (rotl(msgU[1], 1) & rotl(msgU[1], 8)) ^ rotl(msgU[1], 2) ^ keys[it];
                    msgU[0] = tmp;

                    AddStep("Encryption Part (" + partno.ToString("D2") + ") Round : (" + it.ToString("D2") + ") " + print_chipers(ulongToByte(msgU), null), toBinaryString(ulongToByte(msgU)));
                }

                encrypt[i] = msgU[0];
                encrypt[i + 1] = msgU[1];

            }


            return ulongToByte(encrypt);

        }

        public byte[] Decrypt(int partno, byte[] msg, byte[] key)
        {

            ulong[] keyU = byteToUlongArray(key);
            ulong[] msgU = byteToUlongArray(msg);


            ulong[] decrypt = new ulong[msgU.Length];
            for (int i = 0; i < msgU.Length / 2; i++)
            {
                AddStep("Decryption Part (" + partno.ToString("D2") + ") - Başlangıç :" + print_chipers(ulongToByte(msgU), null), toBinaryString(ulongToByte(msgU)));
                ulong[] keys = keyExpand(keyU);

                for (int it = t - 1; it >= 0; it--)
                {
                    ulong tmp = msgU[0];
                    msgU[0] = msgU[1] ^ keys[it] ^ rotl(msgU[0], 2) ^ (rotl(msgU[0], 1) & rotl(msgU[0], 8));
                    msgU[1] = tmp;

                    AddStep("Decryption Part (" + partno.ToString("D2") + ") Round: (" + it.ToString("D2") + ") " + print_chipers(ulongToByte(msgU), null), toBinaryString(ulongToByte(msgU)));

                }

                decrypt[i] = msgU[0];
                decrypt[i + 1] = msgU[1];

            }

            return ulongToByte(decrypt);

        }


        // ANAHTAR GENİŞLETME İŞLEVİ

        private ulong[] keyExpand(ulong[] key)
        {

            ulong[] keys = new ulong[t];
            for (int i = 0; i < m; i++)
            {
                keys[i] = key[i];
            }

            ulong zj = z[j];
            ulong tmp;
            for (int i = m; i < t; i++)
            {
                tmp = rotl(keys[i - 1], 3);
                if (m == 4) tmp = tmp ^ keys[i - 3];
                tmp = tmp ^ rotl(tmp, 1);
                keys[i] = keys[i - m] ^ tmp ^ getNBits(rotl(zj, i - m)) ^ (ulong.MaxValue - 3);

            }
            return keys;
        }


        // ARİTMETİK İŞLEMLER

        //Bit kaydırma döndürme
        private ulong rotl(ulong block, int cant)
        {
            return ((block << cant) + (block >> (64 - cant)));
        }

        //n Anahtarlarını al
        private ulong getNBits(ulong block)
        {
            return block >> (62 - n);
        }


        // DÖNÜŞÜM FONKSİYONLARI

        // Bir bayt dizisini bir ulong dizisine dönüştüren işlev
        public ulong[] byteToUlongArray(byte[] bytes)
        {
            byte[] bword = new byte[WORDSIZE];
            bytes.CopyTo(bword, 0);

            //Kelime dizisini oluşturuyorum (8 bayt)
            ulong[] wrd = new ulong[bword.Length / 8];

            // Baytlardan kelimelere geçiş yapıyorum
            for (int i = 0; i < wrd.Length; i++)
                wrd[i] = BitConverter.ToUInt64(bword, i * 8);

            return wrd;
        }



        public byte[] ulongToByte(ulong array)
        {
            byte[] bytesUlong = BitConverter.GetBytes(array);
            return bytesUlong;
        }

        public byte[] ulongToByte(ulong[] array)
        {
            byte[] bytes = new byte[array.Length * 8];

            for (int i = 0; i < array.Length; i++)
            {
                byte[] bytesUlong = BitConverter.GetBytes(array[i]);
                for (int j = 0; j < bytesUlong.Length; j++)
                {
                    bytes[i * 8 + j] = bytesUlong[j];
                }
            }

            return bytes;
        }

        public string toBinaryString(byte[,] data)
        {
            return toBinaryString(data.Cast<byte>().ToArray());
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


    }

}
