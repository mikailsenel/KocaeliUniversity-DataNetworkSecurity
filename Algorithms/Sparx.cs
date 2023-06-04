using Algorithms.Common.Abstract;
using Algorithms.Common.DataTransferObjects;
using Algorithms.Common.Enums;
using System.Text;

namespace Algorithms
{
    public class Sparx : EncryptionAlgorithm
    {
        private const int KEYSIZE = 128;
        private const int N_STEPS = 8;
        private const int ROUNDS_PER_STEPS = 4;
        private const int N_BRANCHES = 4;
        private const int K_SIZE = 4;
        private const int WORDSIZE = 16; //byte

        public Sparx(InputDto input) : base(input)
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



            UInt16[] usKey = byteToUInt16(key, 0);

            byte[] chiperText = new byte[plainText.Length % WORDSIZE == 0 ? plainText.Length : plainText.Length + (WORDSIZE - (plainText.Length % WORDSIZE))];

            plainText.CopyTo(chiperText, 0);


            UInt16[][] k = new UInt16[N_BRANCHES * N_STEPS + 1][];
            for (int i = 0; i < N_BRANCHES * N_STEPS + 1; i++)
            {
                k[i] = new UInt16[2 * ROUNDS_PER_STEPS];
            }

            KeySchedule(ref k, usKey);

            for (int i = 0; i < (chiperText.Length / WORDSIZE); i++)
            {
                byte[] tmp = new byte[WORDSIZE];
                Array.Copy(chiperText, i * WORDSIZE, tmp, 0, WORDSIZE);
                UInt16[] tmpplain = byteToUInt16(tmp, 0);
                SparxEncrypt(i + 1, ref tmpplain, k);
                tmp = uInt16ToByte(tmpplain);
                Array.Copy(tmp, 0, chiperText, i * WORDSIZE, WORDSIZE);
            }

            byte[] encrytpText = new byte[chiperText.Length];

            chiperText.CopyTo(encrytpText, 0);

            for (int i = 0; i < (chiperText.Length / WORDSIZE); i++)
            {
                byte[] tmp = new byte[WORDSIZE];
                Array.Copy(chiperText, i * WORDSIZE, tmp, 0, WORDSIZE);
                UInt16[] tmpchiper = byteToUInt16(tmp, 0);
                SparxDecrypt(i + 1, ref tmpchiper, k);
                tmp = uInt16ToByte(tmpchiper);
                Array.Copy(tmp, 0, chiperText, i * WORDSIZE, WORDSIZE);
            }

            clearlast0(ref chiperText);

            AddStep("Düz metin      : " + BitConverter.ToString(plainText), toBinaryString(plainText));

            AddStep("Anahtar        : " + BitConverter.ToString(key), toBinaryString(key));

            AddStep("Şifreli metin  : " + BitConverter.ToString(encrytpText), toBinaryString(encrytpText));

            AddStep("Çözülmüş metin : " + BitConverter.ToString(chiperText), toBinaryString(chiperText));

            FinalStep(chiperText, outputTypes);


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


        // Bir bayt dizisini bir UInt16 dizisine dönüştüren işlev
        public UInt16[] byteToUInt16(byte[] bytes, int minBytes)
        {

            // Diziyi, oluşturulmuş 2 baytlık (16 bit kelime) grupları olan başka bir diziye aktarıyorum   
            int cant = (bytes.Length % 2 == 0) ? bytes.Length : bytes.Length + (2 - bytes.Length % 2);
            if (cant < minBytes) cant = minBytes;
            byte[] b = new byte[cant];
            bytes.CopyTo(b, 0);

            Console.WriteLine();

            //Kelime dizisini oluşturuyorum (2 bayt)
            UInt16[] c = new UInt16[b.Length / 2];

            // Baytlardan kelimelere geçiş yapıyorum
            for (int i = 0; i < c.Length; i++)
                c[i] = BitConverter.ToUInt16(b, i * 2);

            return c;
        }

        public byte[] uInt16ToByte(UInt16[] array)
        {
            byte[] bytes = new byte[array.Length * 2];

            for (int i = 0; i < array.Length; i++)
            {
                byte[] bytesUlong = BitConverter.GetBytes(array[i]);
                for (int j = 0; j < bytesUlong.Length; j++)
                {
                    bytes[i * 2 + j] = bytesUlong[j];
                }
            }

            return bytes;
        }


        private UInt16 ROTL(UInt16 x, int n)
        {
            return (UInt16)((x << n) | (x >> (16 - n)));
        }

        private void SWAP(ref UInt16 x, ref UInt16 y)
        {
            UInt16 tmp = x;
            x = y;
            y = tmp;
        }

        private void A(ref UInt16 l, ref UInt16 r)
        {
            l = ROTL(l, 9);
            l += r;
            r = ROTL(r, 2);
            r ^= l;
        }

        private void A_inv(ref UInt16 l, ref UInt16 r)
        {
            r ^= l;
            r = ROTL(r, 14);
            l -= r;
            l = ROTL(l, 7);
        }


        private void L4(ref UInt16[] x)
        {
            UInt16 tmp = (UInt16)(x[0] ^ x[1] ^ x[2] ^ x[3]);
            tmp = ROTL(tmp, 8);

            x[4] ^= (UInt16)(x[2] ^ tmp);
            x[5] ^= (UInt16)(x[1] ^ tmp);
            x[6] ^= (UInt16)(x[0] ^ tmp);
            x[7] ^= (UInt16)(x[3] ^ tmp);

            SWAP(ref x[0], ref x[4]);
            SWAP(ref x[1], ref x[5]);
            SWAP(ref x[2], ref x[6]);
            SWAP(ref x[3], ref x[7]);
        }

        private void L4_inv(ref UInt16[] x)
        {
            SWAP(ref x[0], ref x[4]);
            SWAP(ref x[1], ref x[5]);
            SWAP(ref x[2], ref x[6]);
            SWAP(ref x[3], ref x[7]);

            UInt16 tmp = (UInt16)(x[0] ^ x[1] ^ x[2] ^ x[3]);
            tmp = ROTL(tmp, 8);
            x[4] ^= (UInt16)(x[2] ^ tmp);
            x[5] ^= (UInt16)(x[1] ^ tmp);
            x[6] ^= (UInt16)(x[0] ^ tmp);
            x[7] ^= (UInt16)(x[3] ^ tmp);
        }

        private void K_perm_128_128(ref UInt16[] k, UInt16 c)
        {
            UInt16 tmp_0, tmp_1, i;
            A(ref k[0], ref k[1]);
            k[2] += k[0];
            k[3] += k[1];
            A(ref k[4], ref k[5]);
            k[6] += k[4];
            k[7] += (UInt16)(k[5] + c);
            tmp_0 = k[6];
            tmp_1 = k[7];
            for (i = 7; i >= 2; i--)
            {
                k[i] = k[i - 2];
            }
            k[0] = tmp_0;
            k[1] = tmp_1;
        }

        private void KeySchedule(ref UInt16[][] subkeys, UInt16[] masterKey)
        {
            for (int c = 0; c < (N_BRANCHES * N_STEPS + 1); c++)
            {
                for (int i = 0; i < 2 * ROUNDS_PER_STEPS; i++)
                {
                    subkeys[c][i] = masterKey[i];
                }
                K_perm_128_128(ref masterKey, (UInt16)(c + 1));
            }
        }

        private string print_chipers(byte[] state, byte[] keyCells)
        {
            return "S = " + BitConverter.ToString(state.Cast<byte>().ToArray()) + (keyCells == null ? "" : " - TK = " + BitConverter.ToString(keyCells.Cast<byte>().ToArray()));
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


        private void SparxEncrypt(int partno, ref UInt16[] x, UInt16[][] k)
        {

            AddStep("Encryption Part (" + partno.ToString("D2") + ") - Başlangıç : " + print_chipers(uInt16ToByte(x), null), toBinaryString(uInt16ToByte(x)));


            for (int s = 0; s < N_STEPS; s++)
            {
                for (int b = 0; b < N_BRANCHES; b++)
                {
                    for (int r = 0; r < ROUNDS_PER_STEPS; r++)
                    {
                        x[2 * b] ^= k[N_BRANCHES * s + b][2 * r];
                        x[2 * b + 1] ^= k[N_BRANCHES * s + b][2 * r + 1];
                        A(ref x[2 * b], ref x[2 * b + 1]);
                    }
                }
                L4(ref x);
                AddStep("Encryption Part (" + partno.ToString("D2") + ") Steps : (" + s.ToString("D2") + ") " + print_chipers(uInt16ToByte(x), null), toBinaryString(uInt16ToByte(x)));

            }
            for (int b = 0; b < N_BRANCHES; b++)
            {
                x[2 * b] ^= k[N_BRANCHES * N_STEPS][2 * b];
                x[2 * b + 1] ^= k[N_BRANCHES * N_STEPS][2 * b + 1];

                AddStep("Encryption Part (" + partno.ToString("D2") + ") Round : (" + b.ToString("D2") + ") " + print_chipers(uInt16ToByte(x), null), toBinaryString(uInt16ToByte(x)));
            }
        }

        private void SparxDecrypt(int partno, ref UInt16[] x, UInt16[][] k)
        {
            AddStep("Decryption Part (" + partno.ToString("D2") + ") - Başlangıç : " + print_chipers(uInt16ToByte(x), null), toBinaryString(uInt16ToByte(x)));


            for (int b = 0; b < N_BRANCHES; b++)
            {
                x[2 * b] ^= k[N_BRANCHES * N_STEPS][2 * b];
                x[2 * b + 1] ^= k[N_BRANCHES * N_STEPS][2 * b + 1];
                AddStep("Decryption Part (" + partno.ToString("D2") + ") Round : (" + b.ToString("D2") + ") " + print_chipers(uInt16ToByte(x), null), toBinaryString(uInt16ToByte(x)));
            }
            for (int s = N_STEPS - 1; s >= 0; s--)
            {
                L4_inv(ref x);
                for (int b = 0; b < N_BRANCHES; b++)
                {
                    for (int r = ROUNDS_PER_STEPS - 1; r >= 0; r--)
                    {
                        A_inv(ref x[2 * b], ref x[2 * b + 1]);
                        x[2 * b] ^= k[N_BRANCHES * s + b][2 * r];
                        x[2 * b + 1] ^= k[N_BRANCHES * s + b][2 * r + 1];
                    }
                }

                AddStep("Decryption Part (" + partno.ToString("D2") + ") Steps : (" + s.ToString("D2") + ") " + print_chipers(uInt16ToByte(x), null), toBinaryString(uInt16ToByte(x)));

            }
        }



    }
}
