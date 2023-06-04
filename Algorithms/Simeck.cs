using Algorithms.Common.Abstract;
using Algorithms.Common.DataTransferObjects;
using Algorithms.Common.Enums;
using System.Text;

namespace Algorithms
{
    public class Simeck : EncryptionAlgorithm
    {
        const int BLOCK_SIZE = 64; // blok boyutu (bit)
        const int KEY_SIZE = 128; // key boyutu (bit)
        const int WORDSIZE = 8; //byte
        const int NUM_ROUNDS = 44;

        public Simeck(InputDto input) : base(input)
        {
        }

        protected override void Initial(string inputKey, DataTypes inputTypes, DataTypes outputTypes)
        {

            byte[] plainText = ByteValue;

            string keyHexString = inputKey;

            if (keyHexString.Length != (KEY_SIZE / 8) * 2) // Her bir byte 2 hexadecimal karakterle temsil edilir
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

                //normal ctr siz hali
                //tmpplain = Encrypt(i + 1, tmpplain, key);

                //blogu chiper text (plain) e yerlestir
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

                //normal ctr siz hali
                //tmpchiper = Decrypt(i + 1, tmpcipher, key);

                //blogu chiper text (plain) e yerlestir
                Array.Copy(tmpcipher, 0, chiperText, i * WORDSIZE, WORDSIZE);
            }

            clearlast0(ref chiperText);


            AddStep("Düz metin      : " + toOut(plainText, outputTypes), toBinaryString(plainText));

            AddStep("Anahtar        : " + BitConverter.ToString(key), toBinaryString(key));

            AddStep("Şifreli metin  : " + BitConverter.ToString(encrytpText), toBinaryString(encrytpText));

            AddStep("Çözülmüş metin : " + toOut(chiperText, outputTypes), toBinaryString(chiperText));

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

        // Bir bayt dizisini bir ulong dizisine dönüştüren işlev
        public uint[] byteToUints(byte[] bytes, int minBytes)
        {

            // Diziyi, 4 baytlık (32 bitlik uint) grupların oluşturduğu başka bir diziye geçiriyorum   
            int cant = (bytes.Length % 4 == 0) ? bytes.Length : bytes.Length + (4 - bytes.Length % 4);
            if (cant < minBytes) cant = minBytes;
            byte[] b = new byte[cant];
            bytes.CopyTo(b, 0);

            Console.WriteLine();


            uint[] c = new uint[b.Length / 4];

            for (int i = 0; i < c.Length; i++)
                c[i] = BitConverter.ToUInt32(b, i * 4);

            return c;
        }

        // 32 bitlik bir tamsayıyı r bit sola döndürme
        private uint LROT32(uint x, int r)
        {
            return (x << r) | (x >> (32 - r));
        }

        // Bir tur şifreleme gerçekleştirme
        private void ROUND64(uint key, ref uint lft, ref uint rgt)
        {
            uint tmp = lft;
            lft = (lft & LROT32(lft, 5)) ^ LROT32(lft, 1) ^ rgt ^ key;
            rgt = tmp;
        }

        private static string print_chipers(byte[] state, byte[] keyCells)
        {
            return "S = " + BitConverter.ToString(state.Cast<byte>().ToArray()) + (keyCells == null ? "" : " - TK = " + BitConverter.ToString(keyCells.Cast<byte>().ToArray()));
        }


        public static void clearlast0(ref Byte[] chiperText)
        {
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
            byte[] tmpreturn = new byte[deger.Length * sizeof(uint)];

            for (int i = 0; i < deger.Length; i++)
            {
                byte[] barray = System.BitConverter.GetBytes(deger[i]);
                for (int j = 0; j < barray.Length; j++)
                {
                    tmpreturn[i * sizeof(uint) + j] = barray[j];
                }
            }

            return tmpreturn;
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

        // NUM_ROUND kadar key listesi hazirlama
        public uint[] Keylist(byte[] masterkey)
        {
            uint[] keys = byteToUints(masterkey, 0);

            uint[] key0list = new uint[NUM_ROUNDS];

            uint temp;

            uint constant = 0xFFFFFFFC;
            ulong sequence = 0x938BCA3083F;

            for (int i = 0; i < NUM_ROUNDS; ++i)
            {
                key0list[i] = keys[0];

                constant &= 0xFFFFFFFC;
                constant |= (uint)(sequence & 1);

                sequence >>= 1;
                ROUND64(constant, ref keys[1], ref keys[0]);

                temp = keys[1];
                keys[1] = keys[2];
                keys[2] = keys[3];
                keys[3] = temp;

            }

            return key0list;
        }

        // 64 bitlik bir düz metni 128 bitlik bir anahtarla şifreleme
        public byte[] Encrypt(int partno, byte[] bplaintext, byte[] masterKey)
        {

            uint[] keylist = Keylist(masterKey);

            uint[] ciphertext = byteToUints(bplaintext, 0);

            AddStep("Encryption Part (" + partno.ToString("D2") + ") - Başlangıç  " + print_chipers(bplaintext, null), toBinaryString(bplaintext));

            for (int i = 0; i < NUM_ROUNDS; ++i)
            {
                ROUND64(keylist[i], ref ciphertext[1], ref ciphertext[0]);
                AddStep("Encryption Part (" + partno.ToString("D2") + ") Round : (" + i.ToString("D2") + ") " + print_chipers(uinttoByte(ciphertext), null), toBinaryString(uinttoByte(ciphertext)));

            }
            return uinttoByte(ciphertext);
        }


        // 128 bit anahtar ile 64 bit düz metnin şifresini çözme
        public byte[] Decrypt(int partno, byte[] bplaintext, byte[] masterKey)
        {

            uint[] keylist = Keylist(masterKey);
            uint[] ciphertext = byteToUints(bplaintext, 0);

            AddStep("Decryption Part (" + partno.ToString("D2") + ") - Başlangıç  " + print_chipers(bplaintext, null), toBinaryString(bplaintext));


            for (int i = NUM_ROUNDS - 1; i >= 0; --i)
            {
                ROUND64(keylist[i], ref ciphertext[0], ref ciphertext[1]);

                AddStep("Decryption Part (" + partno.ToString("D2") + ") Round : (" + i.ToString("D2") + ") " + print_chipers(uinttoByte(ciphertext), null), toBinaryString(uinttoByte(ciphertext)));
            }

            return uinttoByte(ciphertext);
        }

        /*
        public byte[] GetBigEndianBytes(UInt32 val, bool isLittleEndian)
        {
            UInt32 bigEndian = val;
            if (isLittleEndian)
            {
                bigEndian = (val & 0x000000FFU) << 24 | (val & 0x0000FF00U) << 8 |
                     (val & 0x00FF0000U) >> 8 | (val & 0xFF000000U) >> 24;
            }
            return BitConverter.GetBytes(bigEndian);
        }
        */
    }




}
