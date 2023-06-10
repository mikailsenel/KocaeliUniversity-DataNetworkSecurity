using Algorithms.Common.Abstract;
using Algorithms.Common.DataTransferObjects;
using Algorithms.Common.Enums;
using System.Diagnostics.Metrics;
using System.Text;
using System.Linq;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace Algorithms
{
    public class Sea : EncryptionAlgorithm
    {
        private const int WORDSIZE = 6; //byte
        private const int HALFWORDSIZE = WORDSIZE / 2;
        private const int LEFT = 0;
        private const int RIGHT = 1;
        private const int TEXT_KEY_LENGHT = 48; //Bit
        private const int BYTEBIT = 8; // Bit cinsinden 1 bayt uzunluğu
        private const int NUM_ROUNDS = (3 * TEXT_KEY_LENGHT / 4) + 2 * ((TEXT_KEY_LENGHT / (2 * BYTEBIT)) + (BYTEBIT / 2)) + 1; // Tur sayısı
        private const int HALF_TK_LENGHT = TEXT_KEY_LENGHT / 2; // Blok bit sayısı
        private bool CTRMODU = false;

        public Sea(InputDto input) : base(input)
        {
        }

        protected override void Initial(string inputKey, DataTypes inputTypes, DataTypes outputTypes)
        {

            byte[] plainText = ByteValue;

            string keyHexString = inputKey;

            if (keyHexString.Length != (TEXT_KEY_LENGHT / 8) * 2) // Her bir byte 2 hexadecimal karakterle temsil edilir
            {
                throw new ArgumentException("Geçersiz anahtar uzunluğu. Anahtar " + TEXT_KEY_LENGHT.ToString() + " bit (" + WORDSIZE.ToString() + " byte) olmalıdır.");
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
                    byte[] tmpenc = Encrypt(i + 1, byteToUints(tmpnonce, 0), byteToUints(key, 0));

                    //çıkan şifreli sabiti plain text ile xor la
                    tmpplain = Xor(tmpplain, tmpenc);
                    #endregion
                }
                else
                {
                    //normal ctr siz hali
                    tmpplain = Encrypt(i + 1, byteToUints(tmpplain, 0), byteToUints(key, 0));
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
                byte[] tmpchiper = new byte[WORDSIZE];
                Array.Copy(chiperText, i * WORDSIZE, tmpchiper, 0, WORDSIZE);
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
                    byte[] tmpenc = Encrypt(i + 1, byteToUints(tmpnonce, 0), byteToUints(key, 0));

                    //çıkan şifreli sabiti plain text ile xor la
                    tmpchiper = Xor(tmpchiper, tmpenc);
                    #endregion
                }
                else
                {
                    //normal ctr siz hali
                    tmpchiper = Decrypt(i + 1, byteToUints(tmpchiper, 0), byteToUints(key, 0));
                }

                //blogu chiper text (plain) e yerlestir
                Array.Copy(tmpchiper, 0, chiperText, i * WORDSIZE, WORDSIZE);

            }

            clearlast0(ref chiperText);

            AddStep("Düz metin      : " + toOut(plainText, outputTypes), toBinaryString(plainText));

            AddStep("Anahtar        : " + BitConverter.ToString(key), toBinaryString(key));

            AddStep("Şifreli metin  : " + BitConverter.ToString(encrytpText), toBinaryString(encrytpText));

            AddStep("Çözülmüş metin : " + toOut(chiperText, outputTypes), toBinaryString(chiperText));

            //FinalStep(BitConverter.ToString(chiperText), DataTypes.Hex, outputTypes);
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

        // Bitwise XOR operation
        private uint Xor(uint a, uint b)
        {
            return a ^ b;
        }


        public void clearlast0(ref Byte[] chiperText)
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



        private byte[] uinttoByte(uint deger)
        {
            return System.BitConverter.GetBytes(deger);
        }

        private byte[] uinttoByte(uint[] deger)
        {
            byte[] tmpreturn = new byte[deger.Length * HALFWORDSIZE];

            for (int i = 0; i < deger.Length; i++)
            {
                byte[] barray = System.BitConverter.GetBytes(deger[i]);
                for (int j = 0; j < HALFWORDSIZE; j++)
                {
                    tmpreturn[i * HALFWORDSIZE + j] = barray[j];
                }
            }

            return tmpreturn;
        }

        // Bir bayt dizisini bir uint dizisine dönüştüren işlev
        public uint[] byteToUints(byte[] bytes, int minBytes)
        {
            // Diziyi, 4 baytlık (32 bitlik uint) grupların oluşturduğu başka bir diziye geçiriyorum   
            int cant = (bytes.Length % WORDSIZE == 0) ? bytes.Length : bytes.Length + (WORDSIZE - bytes.Length % WORDSIZE);
            if (cant < minBytes) cant = minBytes;
            byte[] b = new byte[cant];
            bytes.CopyTo(b, 0);


            uint[] c = new uint[b.Length / HALFWORDSIZE];

            for (int i = 0; i < c.Length; i++)
            {
                byte[] tmp = new byte[4];

                Array.Copy(b, i * HALFWORDSIZE, tmp, 0, HALFWORDSIZE);

                c[i] = BitConverter.ToUInt32(tmp, 0);
            }

            return c;
        }

        // Toplama modulo 2^b işlemi
        private uint AddModulo(uint a, uint b, uint blksize)
        {

            byte[] blkbytea = uinttoByte(a);
            byte[] blkbyteb = uinttoByte(b);
            byte[] blktmp = new byte[4];

            for (int i = 0; i < 3; i++)
            {
                blktmp[i] = (byte)(((UInt16)(blkbytea[i] + blkbyteb[i])) % (1u << (int)blksize));
            }

            return BitConverter.ToUInt32(blktmp, 0);
        }

        // Sbox Yerine koyma işlemi
        private uint SubstitutionBox(uint x)
        {
            uint[] substitutionTable = { 0, 5, 6, 7, 4, 3, 1, 2 };

            uint result = 0;

            //24 blok uzunluğu 3 er bit işleme al
            for (int i = 0; i < (HALF_TK_LENGHT); i += 3)
            {
                uint word = (x >> i) & 0x7; //3 bitlik sözcüğü ayıkla                                            
                result |= (substitutionTable[word] << i); // Yerine koyma uygulayın

            }

            return result;
        }

        // Kelime döndürme R işlemi
        private uint RotateWord(uint x)
        {
            byte[] blkbytex = uinttoByte(x);

            byte tmp = blkbytex[2];
            blkbytex[2] = blkbytex[1];
            blkbytex[1] = blkbytex[0];
            blkbytex[0] = tmp;

            return BitConverter.ToUInt32(blkbytex, 0);
        }

        private uint RotateWordInv(uint x)
        {
            byte[] blkbytex = uinttoByte(x);

            byte tmp = blkbytex[0];
            blkbytex[0] = blkbytex[1];
            blkbytex[1] = blkbytex[2];
            blkbytex[2] = tmp;

            return BitConverter.ToUInt32(blkbytex, 0);

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

        // Bit döndürme r işlemi
        private uint RotateBits(uint x)
        {
            byte[] blkbytex = uinttoByte(x);

            byte word1 = (byte)(blkbytex[0] & 0x7);
            blkbytex[0] = (byte)((word1 << 5) | (blkbytex[0] >> 3));
            byte word2 = (byte)(blkbytex[2] >> 5);
            blkbytex[2] = (byte)(((blkbytex[2] << 3) & 0xFF) | word2);
            return BitConverter.ToUInt32(blkbytex, 0);
        }

        //ROUND sayısı kadar Key listsi turetme 
        private uint[,] KeyList(uint[] key)
        {
            uint KL = key[0];
            uint KR = key[1];

            uint[,] keylist = new uint[NUM_ROUNDS, 2];
            uint to_down_nr = (uint)Math.Floor((decimal)NUM_ROUNDS / 2);
            uint to_up_nr = (uint)Math.Ceiling((decimal)NUM_ROUNDS / 2);

            keylist[0, 0] = KL;
            keylist[0, 1] = KR;

            for (uint i = 1; i <= to_down_nr; i++)
            {
                uint Ci = i;

                uint AddM = (AddModulo(KR, Ci, 8));
                uint SubBox = SubstitutionBox(AddM);
                uint RotBit = RotateBits(SubBox);
                uint RotWord = RotateWord(RotBit);
                uint KRi = KL ^ RotWord;
                uint KLi = KR;
                KL = KLi;
                KR = KRi;
                keylist[i, 0] = KL;
                keylist[i, 1] = KR;

            }

            uint temp = KL;
            KL = KR;
            KR = temp;

            for (uint i = to_up_nr; i < NUM_ROUNDS; i++)
            {
                uint Ci = i;//(r - i);                 
                uint AddM = (AddModulo(KR, Ci, 8));
                uint SubBox = SubstitutionBox(AddM);
                uint RotBit = RotateBits(SubBox);
                uint RotWord = RotateWord(RotBit);
                uint KRi = KL ^ RotWord;
                uint KLi = KR;
                KL = KLi;
                KR = KRi;

                keylist[i, 0] = KL;
                keylist[i, 1] = KR;

            }

            return keylist;
        }


        // SEA şi̇freleme turu
        private void EncryptionRound(ref uint L, ref uint R, uint K)
        {
            uint temp = R;
            R = Xor(RotateWord(L), RotateBits(SubstitutionBox(AddModulo(R, K, 8))));
            L = temp;
        }

        // SEA şifre çözme turu
        private void DecryptionRound(ref uint L, ref uint R, uint K)
        {
            uint temp = R;
            R = RotateWordInv(Xor(L, RotateBits(SubstitutionBox(AddModulo(R, K, 8)))));
            L = temp;

        }

        private string print_chipers(byte[] state, byte[] keyCells)
        {
            return "S = " + BitConverter.ToString(state.Cast<byte>().ToArray()) + (keyCells == null ? "" : " - TK = " + BitConverter.ToString(keyCells.Cast<byte>().ToArray()));
        }


        // SEA şifreleme işlevi 
        private byte[] Encrypt(int partno, uint[] plaintext, uint[] key)
        {
            uint L = plaintext[LEFT];
            uint R = plaintext[RIGHT];
            uint KL;
            uint KR;

            uint[,] keylist = KeyList(key);

            uint to_up_nr = (uint)Math.Ceiling((decimal)NUM_ROUNDS / 2);

            Console.WriteLine();

            AddStep("Encryption Part (" + partno.ToString("D2") + ") - Başlangıç  " + print_chipers(uinttoByte(plaintext), null), toBinaryString(uinttoByte(plaintext)));

            int tur = 0;

            for (uint i = 1; i <= to_up_nr; i++)
            {
                KR = keylist[i - 1, RIGHT];

                EncryptionRound(ref L, ref R, KR);

                plaintext[LEFT] = R;
                plaintext[RIGHT] = L;
                tur++;
                AddStep("Encryption Part (" + partno.ToString("D2") + ") Round : (" + tur.ToString("D2") + ") " + print_chipers(uinttoByte(plaintext), null), toBinaryString(uinttoByte(plaintext)));
            }

            for (uint i = to_up_nr + 1; i <= NUM_ROUNDS; i++)
            {
                KL = keylist[i - 1, 0];

                EncryptionRound(ref L, ref R, KL);

                plaintext[LEFT] = R;
                plaintext[RIGHT] = L;
                tur++;
                AddStep("Encryption Part (" + partno.ToString("D2") + ") Round : (" + tur.ToString("D2") + ") " + print_chipers(uinttoByte(plaintext), null), toBinaryString(uinttoByte(plaintext)));
            }

            plaintext[LEFT] = R;
            plaintext[RIGHT] = L;

            return uinttoByte(plaintext);
        }

        // SEA şifre çözme işlevi 
        private byte[] Decrypt(int partno, uint[] ciphertext, uint[] key)
        {
            uint L = ciphertext[LEFT];
            uint R = ciphertext[RIGHT];
            uint KL;
            uint KR;

            uint[,] keylist = KeyList(key);

            uint to_up_nr = (uint)Math.Ceiling((decimal)NUM_ROUNDS / 2);

            Console.WriteLine();
            AddStep("Decryption Part (" + partno.ToString("D2") + ") - Başlangıç  " + print_chipers(uinttoByte(ciphertext), null), toBinaryString(uinttoByte(ciphertext)));

            int tur = 0;

            for (uint i = NUM_ROUNDS; i >= to_up_nr + 1; i--)
            {
                KL = keylist[i - 1, LEFT];

                DecryptionRound(ref L, ref R, KL);

                ciphertext[LEFT] = R;
                ciphertext[RIGHT] = L;
                tur++;
                AddStep("Decryption Part (" + partno.ToString("D2") + ") Round : (" + tur.ToString("D2") + ") " + print_chipers(uinttoByte(ciphertext), null), toBinaryString(uinttoByte(ciphertext)));
            }


            for (uint i = to_up_nr; i >= 1; i--)
            {
                KR = keylist[i - 1, RIGHT];

                DecryptionRound(ref L, ref R, KR);

                ciphertext[LEFT] = R;
                ciphertext[RIGHT] = L;
                tur++;
                AddStep("Decryption Part (" + partno.ToString("D2") + ") Round : (" + tur.ToString("D2") + ") " + print_chipers(uinttoByte(ciphertext), null), toBinaryString(uinttoByte(ciphertext)));
            }

            ciphertext[LEFT] = R;
            ciphertext[RIGHT] = L;

            return uinttoByte(ciphertext);
        }



    }
}


