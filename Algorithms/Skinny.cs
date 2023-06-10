using Algorithms.Common.Abstract;
using Algorithms.Common.DataTransferObjects;
using Algorithms.Common.Enums;
using System.Text;

namespace Algorithms
{
    public class Skinny : EncryptionAlgorithm
    {
        // SKINNY algoritmasının parametreleri

        private const int BLOCKSIZE = 128;
        private const int KEYSIZE = 128;
        private const int ROUND = 40;
        private const int WORDSIZE = 16;
        private bool CTRMODU = false;

        // 8-bit Sbox
        private static readonly byte[] sbox_8 = {
            0x65, 0x4c, 0x6a, 0x42, 0x4b, 0x63, 0x43, 0x6b, 0x55, 0x75, 0x5a, 0x7a, 0x53, 0x73, 0x5b, 0x7b,
            0x35, 0x8c, 0x3a, 0x81, 0x89, 0x33, 0x80, 0x3b, 0x95, 0x25, 0x98, 0x2a, 0x90, 0x23, 0x99, 0x2b,
            0xe5, 0xcc, 0xe8, 0xc1, 0xc9, 0xe0, 0xc0, 0xe9, 0xd5, 0xf5, 0xd8, 0xf8, 0xd0, 0xf0, 0xd9, 0xf9,
            0xa5, 0x1c, 0xa8, 0x12, 0x1b, 0xa0, 0x13, 0xa9, 0x05, 0xb5, 0x0a, 0xb8, 0x03, 0xb0, 0x0b, 0xb9,
            0x32, 0x88, 0x3c, 0x85, 0x8d, 0x34, 0x84, 0x3d, 0x91, 0x22, 0x9c, 0x2c, 0x94, 0x24, 0x9d, 0x2d,
            0x62, 0x4a, 0x6c, 0x45, 0x4d, 0x64, 0x44, 0x6d, 0x52, 0x72, 0x5c, 0x7c, 0x54, 0x74, 0x5d, 0x7d,
            0xa1, 0x1a, 0xac, 0x15, 0x1d, 0xa4, 0x14, 0xad, 0x02, 0xb1, 0x0c, 0xbc, 0x04, 0xb4, 0x0d, 0xbd,
            0xe1, 0xc8, 0xec, 0xc5, 0xcd, 0xe4, 0xc4, 0xed, 0xd1, 0xf1, 0xdc, 0xfc, 0xd4, 0xf4, 0xdd, 0xfd,
            0x36, 0x8e, 0x38, 0x82, 0x8b, 0x30, 0x83, 0x39, 0x96, 0x26, 0x9a, 0x28, 0x93, 0x20, 0x9b, 0x29,
            0x66, 0x4e, 0x68, 0x41, 0x49, 0x60, 0x40, 0x69, 0x56, 0x76, 0x58, 0x78, 0x50, 0x70, 0x59, 0x79,
            0xa6, 0x1e, 0xaa, 0x11, 0x19, 0xa3, 0x10, 0xab, 0x06, 0xb6, 0x08, 0xba, 0x00, 0xb3, 0x09, 0xbb,
            0xe6, 0xce, 0xea, 0xc2, 0xcb, 0xe3, 0xc3, 0xeb, 0xd6, 0xf6, 0xda, 0xfa, 0xd3, 0xf3, 0xdb, 0xfb,
            0x31, 0x8a, 0x3e, 0x86, 0x8f, 0x37, 0x87, 0x3f, 0x92, 0x21, 0x9e, 0x2e, 0x97, 0x27, 0x9f, 0x2f,
            0x61, 0x48, 0x6e, 0x46, 0x4f, 0x67, 0x47, 0x6f, 0x51, 0x71, 0x5e, 0x7e, 0x57, 0x77, 0x5f, 0x7f,
            0xa2, 0x18, 0xae, 0x16, 0x1f, 0xa7, 0x17, 0xaf, 0x01, 0xb2, 0x0e, 0xbe, 0x07, 0xb7, 0x0f, 0xbf,
            0xe2, 0xca, 0xee, 0xc6, 0xcf, 0xe7, 0xc7, 0xef, 0xd2, 0xf2, 0xde, 0xfe, 0xd7, 0xf7, 0xdf, 0xff
        };
        private static readonly byte[] sbox_8_inv = {
            0xac, 0xe8, 0x68, 0x3c, 0x6c, 0x38, 0xa8, 0xec, 0xaa, 0xae, 0x3a, 0x3e, 0x6a, 0x6e, 0xea, 0xee,
            0xa6, 0xa3, 0x33, 0x36, 0x66, 0x63, 0xe3, 0xe6, 0xe1, 0xa4, 0x61, 0x34, 0x31, 0x64, 0xa1, 0xe4,
            0x8d, 0xc9, 0x49, 0x1d, 0x4d, 0x19, 0x89, 0xcd, 0x8b, 0x8f, 0x1b, 0x1f, 0x4b, 0x4f, 0xcb, 0xcf,
            0x85, 0xc0, 0x40, 0x15, 0x45, 0x10, 0x80, 0xc5, 0x82, 0x87, 0x12, 0x17, 0x42, 0x47, 0xc2, 0xc7,
            0x96, 0x93, 0x03, 0x06, 0x56, 0x53, 0xd3, 0xd6, 0xd1, 0x94, 0x51, 0x04, 0x01, 0x54, 0x91, 0xd4,
            0x9c, 0xd8, 0x58, 0x0c, 0x5c, 0x08, 0x98, 0xdc, 0x9a, 0x9e, 0x0a, 0x0e, 0x5a, 0x5e, 0xda, 0xde,
            0x95, 0xd0, 0x50, 0x05, 0x55, 0x00, 0x90, 0xd5, 0x92, 0x97, 0x02, 0x07, 0x52, 0x57, 0xd2, 0xd7,
            0x9d, 0xd9, 0x59, 0x0d, 0x5d, 0x09, 0x99, 0xdd, 0x9b, 0x9f, 0x0b, 0x0f, 0x5b, 0x5f, 0xdb, 0xdf,
            0x16, 0x13, 0x83, 0x86, 0x46, 0x43, 0xc3, 0xc6, 0x41, 0x14, 0xc1, 0x84, 0x11, 0x44, 0x81, 0xc4,
            0x1c, 0x48, 0xc8, 0x8c, 0x4c, 0x18, 0x88, 0xcc, 0x1a, 0x1e, 0x8a, 0x8e, 0x4a, 0x4e, 0xca, 0xce,
            0x35, 0x60, 0xe0, 0xa5, 0x65, 0x30, 0xa0, 0xe5, 0x32, 0x37, 0xa2, 0xa7, 0x62, 0x67, 0xe2, 0xe7,
            0x3d, 0x69, 0xe9, 0xad, 0x6d, 0x39, 0xa9, 0xed, 0x3b, 0x3f, 0xab, 0xaf, 0x6b, 0x6f, 0xeb, 0xef,
            0x26, 0x23, 0xb3, 0xb6, 0x76, 0x73, 0xf3, 0xf6, 0x71, 0x24, 0xf1, 0xb4, 0x21, 0x74, 0xb1, 0xf4,
            0x2c, 0x78, 0xf8, 0xbc, 0x7c, 0x28, 0xb8, 0xfc, 0x2a, 0x2e, 0xba, 0xbe, 0x7a, 0x7e, 0xfa, 0xfe,
            0x25, 0x70, 0xf0, 0xb5, 0x75, 0x20, 0xb0, 0xf5, 0x22, 0x27, 0xb2, 0xb7, 0x72, 0x77, 0xf2, 0xf7,
            0x2d, 0x79, 0xf9, 0xbd, 0x7d, 0x29, 0xb9, 0xfd, 0x2b, 0x2f, 0xbb, 0xbf, 0x7b, 0x7f, 0xfb, 0xff
        };

        // ShiftAndSwitchRows permütasyonu
        private static readonly byte[] P = { 0, 1, 2, 3, 7, 4, 5, 6, 10, 11, 8, 9, 13, 14, 15, 12 };
        private static readonly byte[] P_inv = { 0, 1, 2, 3, 5, 6, 7, 4, 10, 11, 8, 9, 15, 12, 13, 14 };

        // Tweakey permütasyonu
        private static readonly byte[] TWEAKEY_P = { 9, 15, 8, 13, 10, 14, 12, 11, 0, 1, 2, 3, 4, 5, 6, 7 };
        private static readonly byte[] TWEAKEY_P_inv = { 8, 9, 10, 11, 12, 13, 14, 15, 2, 0, 4, 7, 6, 3, 5, 1 };

        // Round sabitler
        private static readonly byte[] RC = {
            0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B, 0x37, 0x2F,
            0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E, 0x1D, 0x3A, 0x35, 0x2B,
            0x16, 0x2C, 0x18, 0x30, 0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E,
            0x1C, 0x38, 0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A,
            0x34, 0x29, 0x12, 0x24, 0x08, 0x11, 0x22, 0x04, 0x09, 0x13,
            0x26, 0x0C, 0x19, 0x32, 0x25, 0x0A, 0x15, 0x2A, 0x14, 0x28,
            0x10, 0x20
        };

        public Skinny(InputDto input) : base(input)
        {
        }

        protected override void Initial(string inputKey, DataTypes inputTypes, DataTypes outputTypes)
        {

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

            #region Counter (CTR) modu
            //ctrsabit
            byte[] nonce = GetByteArray(WORDSIZE);
            uint ctrcounter = 0, ncounter;
            //tmpsabit
            byte[] tmpnonce = new byte[WORDSIZE];
            //tmpsabit e ctrsabit kopyala
            nonce.CopyTo(tmpnonce, 0);
            #endregion

            for (int i = 0; i < (chiperText.Length / WORDSIZE); i++)
            {
                byte[] tmpplain = new byte[WORDSIZE];
                Array.Copy(chiperText, i * WORDSIZE, tmpplain, 0, WORDSIZE);

                if (CTRMODU)
                {
                    #region Counter (CTR) modu
                    //4 byte int32 ye cevir ve ctrcounter ekle
                    ncounter = BitConverter.ToUInt32(nonce, 0) + ctrcounter;
                    //degeri sonraki adım icin arttır
                    ctrcounter++;
                    //yeni int32 (4 byte degeri tmpsabit e btye olarak ata
                    Array.Copy(uinttoByte(ncounter), 0, tmpnonce, 0, 4);
                    //tmpsabit i sifrele                
                    byte[] tmpenc = Encrypt(i + 1, tmpnonce, key);
                    //çıkan şifreli sabiti plain text ile xor la
                    tmpplain = Xor(tmpplain, tmpenc);
                    #endregion
                }
                else
                {
                    //normal ctr siz hali
                    tmpplain = Encrypt(i + 1, tmpplain, key);
                }
                //blogu chiper text e yerlestir
                Array.Copy(tmpplain, 0, chiperText, i * WORDSIZE, WORDSIZE);
            }

            byte[] encrytpText = new byte[chiperText.Length];

            chiperText.CopyTo(encrytpText, 0);

            #region Counter (CTR) modu
            ctrcounter = 0;
            Array.Copy(nonce, 0, tmpnonce, 0, WORDSIZE);
            #endregion

            for (int i = 0; i < (chiperText.Length / WORDSIZE); i++)
            {
                byte[] tmpcipher = new byte[WORDSIZE];
                Array.Copy(chiperText, i * WORDSIZE, tmpcipher, 0, WORDSIZE);

                if (CTRMODU)
                {
                    #region Counter (CTR) modu
                    //4 byte int32 ye cevir ve ctrcounter ekle
                    ncounter = BitConverter.ToUInt32(nonce, 0) + ctrcounter;
                    //degeri sonraki adım icin arttır
                    ctrcounter++;
                    //yeni int32 (4 byte degeri tmpsabit e btye olarak ata
                    Array.Copy(uinttoByte(ncounter), 0, tmpnonce, 0, 4);
                    //tmpsabit i sifrele                
                    byte[] tmpenc = Encrypt(i + 1, tmpnonce, key);
                    //çıkan şifreli sabiti plain text ile xor la
                    tmpcipher = Xor(tmpcipher, tmpenc);
                    #endregion
                }
                else
                {
                    //normal ctr siz hali
                    tmpcipher = Decrypt(i + 1, tmpcipher, key);
                }
                //blogu chiper text (plain) e yerlestir
                Array.Copy(tmpcipher, 0, chiperText, i * WORDSIZE, WORDSIZE);
            }

            clearlast0(ref chiperText);


            AddStep("Düz metin      : " + toOut(plainText, outputTypes), toBinaryString(plainText));

            AddStep("Anahtar        : " + BitConverter.ToString(key), toBinaryString(key));

            AddStep("Şifreli metin  : " + BitConverter.ToString(encrytpText), toBinaryString(encrytpText));

            AddStep("Çözülmüş metin : " + toOut(chiperText, outputTypes), toBinaryString(chiperText));


        }


        private static string print_chipers(byte[,] state, byte[,] keyCells)
        {
            return "S = " + BitConverter.ToString(state.Cast<byte>().ToArray()) + (keyCells == null ? "" : " - TK = " + BitConverter.ToString(keyCells.Cast<byte>().ToArray()));
        }


        // Alt anahtarı çıkarın ve dahili duruma uygulayın (birlikte XORlanmış iki üst satır olmalıdır), ardından tweakey durumunu güncelleyin
        private static void AddKey(byte[,] state, byte[,] keyCells)
        {
            int i, j, k;
            byte pos;
            byte[,] keyCells_tmp = new byte[4, 4];

            // alt anahtarı dahili duruma uygula
            for (i = 0; i <= 1; i++)
            {
                for (j = 0; j < 4; j++)
                {
                    state[i, j] ^= keyCells[i, j];
                }
            }

            // alt anahtar durumlarını permütasyon ile güncelleyin

            for (i = 0; i < 4; i++)
            {
                for (j = 0; j < 4; j++)
                {
                    // TWEAKEY permütasyonunun uygulanması
                    pos = TWEAKEY_P[j + 4 * i];
                    keyCells_tmp[i, j] = keyCells[pos >> 2, pos & 0x3];
                }
            }




            for (i = 0; i < 4; i++)
            {
                for (j = 0; j < 4; j++)
                {
                    keyCells[i, j] = keyCells_tmp[i, j];
                }
            }

        }



        // Alt anahtarı çıkarın ve dahili duruma uygulayın (birlikte XORlanmış iki üst satır olmalıdır), ardından tweakey durumunu güncelleyin (ters fonksiyon}
        private static void AddKey_inv(byte[,] state, byte[,] keyCells)
        {
            int i, j;
            byte pos;
            byte[,] keyCells_tmp = new byte[4, 4];

            // alt anahtar durumlarını permütasyon ile güncelleyin

            for (i = 0; i < 4; i++)
            {
                for (j = 0; j < 4; j++)
                {
                    //ters TWEAKEY permütasyonunun uygulaması
                    pos = TWEAKEY_P_inv[j + 4 * i];
                    keyCells_tmp[i, j] = keyCells[pos >> 2, pos & 0x3];
                }
            }




            for (i = 0; i < 4; i++)
            {
                for (j = 0; j < 4; j++)
                {
                    keyCells[i, j] = keyCells_tmp[i, j];
                }
            }



            // alt anahtarı dahili duruma uygula
            for (i = 0; i <= 1; i++)
            {
                for (j = 0; j < 4; j++)
                {
                    state[i, j] ^= keyCells[i, j];

                }
            }
        }



        // Sabitleri uygulayın: 6 bit üzerinde bir LFSR sayacı kullanarak, 6 biti dahili durumun ilk 6 bitine XORlarız
        public void AddConstants(byte[,] state, int r)
        {
            state[0, 0] = (byte)(state[0, 0] ^ (RC[r] & 0xf));
            state[1, 0] = (byte)(state[1, 0] ^ ((RC[r] >> 4) & 0x3));
            state[2, 0] = (byte)(state[2, 0] ^ 0x2);
        }



        // 8 bit Sbox uygulayın
        public void SubCell8(byte[,] state)
        {
            int i, j;
            for (i = 0; i < 4; i++)
                for (j = 0; j < 4; j++)
                    state[i, j] = sbox_8[state[i, j]];
        }

        // 8 bit ters Sbox uygulayın
        public void SubCell8_inv(byte[,] state)
        {
            int i, j;
            for (i = 0; i < 4; i++)
                for (j = 0; j < 4; j++)
                    state[i, j] = sbox_8_inv[state[i, j]];
        }


        // ShiftRows işlevini uygulayın
        public void ShiftRows(byte[,] state)
        {
            int i, j, pos;

            byte[,] state_tmp = new byte[4, 4];

            for (i = 0; i < 4; i++)
            {
                for (j = 0; j < 4; j++)
                {
                    //ShiftRows permütasyonunun uygulanması
                    pos = P[j + 4 * i];
                    state_tmp[i, j] = state[pos >> 2, pos & 0x3];
                }
            }

            for (i = 0; i < 4; i++)
            {
                for (j = 0; j < 4; j++)
                {
                    state[i, j] = state_tmp[i, j];
                }
            }
        }


        // Ters ShiftRows işlevini uygulayın
        public void ShiftRows_inv(byte[,] state)
        {
            int i, j, pos;

            byte[,] state_tmp = new byte[4, 4];

            for (i = 0; i < 4; i++)
            {
                for (j = 0; j < 4; j++)
                {
                    //ters ShiftRows permütasyonunun uygulanması
                    pos = P_inv[j + 4 * i];
                    state_tmp[i, j] = state[pos >> 2, pos & 0x3];
                }
            }

            for (i = 0; i < 4; i++)
            {
                for (j = 0; j < 4; j++)
                {
                    state[i, j] = state_tmp[i, j];
                }
            }
        }


        // Doğrusal difüzyon matrisini uygulayın
        //M =
        //1 0 1 1
        //1 0 0 0
        //0 1 1 0
        //1 0 1 0
        public void MixColumn(byte[,] state)
        {
            int j;
            byte temp;

            for (j = 0; j < 4; j++)
            {
                state[1, j] ^= state[2, j];
                state[2, j] ^= state[0, j];
                state[3, j] ^= state[2, j];

                temp = state[3, j];
                state[3, j] = state[2, j];
                state[2, j] = state[1, j];
                state[1, j] = state[0, j];
                state[0, j] = temp;
            }
        }


        // Ters doğrusal difüzyon matrisini uygulayın
        public void MixColumn_inv(byte[,] state)
        {
            int j;
            byte temp;

            for (j = 0; j < 4; j++)
            {
                temp = state[3, j];
                state[3, j] = state[0, j];
                state[0, j] = state[1, j];
                state[1, j] = state[2, j];
                state[2, j] = temp;

                state[3, j] ^= state[2, j];
                state[2, j] ^= state[0, j];
                state[1, j] ^= state[2, j];
            }
        }


        // Skinny'nin şifreleme işlevi
        public byte[] Decrypt(int partno, byte[] input, byte[] userkey)
        {
            byte[] decoded = new byte[input.Length];
            byte[,] state = new byte[4, 4];
            byte[,] dummy = new byte[4, 4];
            byte[,] keyCells = new byte[4, 4];
            int i;


            Array.Clear(keyCells, 0, keyCells.Length);
            //memset(keyCells, 0, 16);

            for (i = 0; i < 16; i++)
            {

                state[i >> 2, i & 0x3] = (byte)(input[i] & 0xFF);
                keyCells[i >> 2, i & 0x3] = (byte)(userkey[i] & 0xFF);

            }

            for (i = ROUND - 1; i >= 0; i--)
            {
                AddKey(dummy, keyCells);
            }


            AddStep("Decryption Part (" + partno.ToString() + ") - Başlangıç :" + print_chipers(state, null), toBinaryString(state));


            for (i = ROUND - 1; i >= 0; i--)
            {
                MixColumn_inv(state);

                ShiftRows_inv(state);

                AddKey_inv(state, keyCells);

                AddConstants(state, i);

                SubCell8_inv(state);

                AddStep("Decryption Part (" + partno.ToString() + ")  Round : (" + i.ToString() + ") " + print_chipers(state, null), toBinaryString(state));

            }



            for (i = 0; i < 16; i++)
                decoded[i] = (byte)(state[i >> 2, i & 0x3] & 0xFF);

            return decoded;
        }



        // Skinny'nin şifreleme fonksiyonu
        public byte[] Encrypt(int partno, byte[] input, byte[] userkey)
        {

            byte[] encoded = new byte[input.Length];
            byte[,] state = new byte[4, 4];
            byte[,] keyCells = new byte[4, 4];
            int i;


            Array.Clear(keyCells, 0, keyCells.Length);

            for (i = 0; i < 16; i++)
            {

                state[i >> 2, i & 0x3] = input[i];
                keyCells[i >> 2, i & 0x3] = userkey[i];


            }

            AddStep("Encryption Part (" + partno.ToString() + ") - Başlangıç : " + print_chipers(state, null), toBinaryString(state));


            for (i = 0; i < ROUND; i++)
            {
                SubCell8(state);

                AddConstants(state, i);

                AddKey(state, keyCells);

                ShiftRows(state);

                MixColumn(state);

                AddStep("Encryption Part (" + partno.ToString() + ") Round : (" + i.ToString() + ") " + print_chipers(state, null), toBinaryString(state));

            }


            for (i = 0; i < 16; i++)
                encoded[i] = (byte)(state[i >> 2, i & 0x3] & 0xFF);

            return encoded;
        }

        private string toOut(byte[] data, DataTypes outputTypes)
        {
            if (outputTypes == DataTypes.Hex)
            {
                return BitConverter.ToString(data);
            }
            else
            if (outputTypes == DataTypes.String)
            {
                return Encoding.ASCII.GetString(data);
            }
            else
            {
                StringBuilder sonuc = new StringBuilder();

                foreach (byte x in data)
                {
                    sonuc.Append((sonuc.Length == 0 ? "" : "-") + ((int)x).ToString("D3"));
                };

                return sonuc.ToString();

            }

        }

        private byte[] GetByteArray(int size)
        {
            Random rnd = new Random();
            byte[] b = new byte[size];
            rnd.NextBytes(b);
            return b;
        }

        // Bitwise XOR operation
        private byte[] Xor(byte[] a, byte[] b)
        {
            byte[] temp = new byte[a.Length];
            for (int i = 0; i < a.Length; i++)
                temp[i] = (byte)(a[i] ^ b[i]);

            return temp;
        }

        private byte[] uinttoByte(uint deger)
        {
            return System.BitConverter.GetBytes(deger);
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

        // Bir diziyi byte'dan bir dizeye dönüştüren işlev (ASCII cinsinden)
        public String bytesToString(byte[] array)
        {
            return Encoding.UTF8.GetString(array, 0, array.Length);

        }





    }
}
