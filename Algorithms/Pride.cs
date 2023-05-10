using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Text;
/*Algoritma tamamlanmıştır*/


namespace Algorithms
{
    public class Pride
    {
      

public void Initial(string input)
{
    // Düz metin ve anahtarı belirleyin
    string plaintext = "This is a secret message";
    string key = "mysecretkey";

    // Düz metni ve anahtarı ekrana yazdırın
    Console.WriteLine("Düz metin: " + plaintext);
    byte[] plaintextBytes = Encoding.ASCII.GetBytes(plaintext);
    string binaryString = GetBinaryString(plaintextBytes);
    Console.WriteLine("Düz metin Binary Gösterimi: " + binaryString);
      
    Console.WriteLine("Anahtar: " + key);
    byte[] keyBytes = Encoding.ASCII.GetBytes(key);
    string binaryString1 = GetBinaryString(keyBytes);
    Console.WriteLine("Düz metin Binary Gösterimi: " + binaryString1);
    // PrideCipher algoritmasını kullanarak düz metni şifreleyin
    string ciphertext = Pride.Encrypt(plaintext, key);

    // Şifreli metni ekrana yazdırın
    Console.WriteLine("Şifreli metin: " + ciphertext);
    byte[] ciphertextBytes = Encoding.ASCII.GetBytes(ciphertext);
    string binaryString2 = GetBinaryString(ciphertextBytes);
    Console.WriteLine("Şifreli metin Binary Gösterimi: " + binaryString2);

    // Şifreli metni aynı anahtar kullanarak çözün
    string decryptedText = Pride.Decrypt(ciphertext, key);

    // Çözülmüş düz metni ekrana yazdırın
    Console.WriteLine("Çözülmüş metin: " + decryptedText);
    byte[] decryptedTextBytes = Encoding.ASCII.GetBytes(decryptedText);
    string binaryString3 = GetBinaryString(decryptedTextBytes);
    Console.WriteLine("Çözülmüş metin Binary Gösterimi: " + binaryString3);

    
}





public static string Encrypt(string plaintext, string key)
{
    // Anahtarın byte dizisine dönüştürülmesi
    byte[] keyBytes = Encoding.UTF8.GetBytes(key);

    // Keystream'in oluşturulması
    byte[] keystream = GenerateKeystream(keyBytes, plaintext.Length);

    // Düz metnin byte dizisine dönüştürülmesi
    byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);

    // Düz metnin keystream ile XOR işlemine tabi tutulması
    byte[] ciphertextBytes = new byte[plaintextBytes.Length];
        for (int i = 0; i < plaintextBytes.Length; i++)
        {
            ciphertextBytes[i] = (byte)(plaintextBytes[i] ^ keystream[i]);
        }

    // Şifreli metnin Base64 formatında string'e dönüştürülmesi
    return Convert.ToBase64String(ciphertextBytes);
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

public static string Decrypt(string ciphertext, string key)
{
    // Anahtarın byte dizisine dönüştürülmesi
    byte[] keyBytes = Encoding.UTF8.GetBytes(key);

    // Keystream'in oluşturulması
    byte[] keystream = GenerateKeystream(keyBytes, ciphertext.Length);

    // Şifreli metnin Base64 formatından byte dizisine dönüştürülmesi
    byte[] ciphertextBytes = Convert.FromBase64String(ciphertext);

    // Şifreli metnin keystream ile XOR işlemine tabi tutulması
    byte[] plaintextBytes = new byte[ciphertextBytes.Length];
    for (int i = 0; i < ciphertextBytes.Length; i++)
    {
        plaintextBytes[i] = (byte)(ciphertextBytes[i] ^ keystream[i]);
    }

    // Çözülmüş düz metnin string'e dönüştürülmesi
    return Encoding.UTF8.GetString(plaintextBytes);
}

private static byte[] GenerateKeystream(byte[] key, int length)
{
    // Keystream'in boyutunu belirleme
    byte[] keystream = new byte[length];

    // Keystream'in oluşturulması
    for (int i = 0; i < length; i++)
    {
        int keyIndex = i % key.Length;
        byte keyByte = key[keyIndex];
        byte keystreamByte = (byte)(keyByte + i);
        keystream[i] = keystreamByte;
    }

    return keystream;
}
}
    
}


        

        
    
