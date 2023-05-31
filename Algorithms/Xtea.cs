using Algorithms.Common.Abstract;

namespace Algorithms;

using System;
using System.Text;
using System.Runtime.InteropServices;
using Algorithms.Common.Enums;
using Algorithms.Common.DataTransferObjects;
using System.Diagnostics;
using System.Collections;

public class Xtea : EncryptionAlgorithm
{
    public Xtea(InputDto inputDto) : base(inputDto)
    {
        
    }

    protected override void Initial(string inputKey, DataTypes inputTypes, DataTypes outputTypes)
    {

        byte[] key = Encoding.ASCII.GetBytes(inputKey);
        byte[] ciphertext;
        byte[] plaintext;

        if (inputKey.Length != 12)
        {
            throw new ArgumentException("Key uzunluğu (12 byte, 96 bit) olmalı.");
        }

        string plaintextR = StringValue;
        Console.WriteLine("Şifrelenecek girdi: " + plaintextR);
        AddStep("Şifrelenecek girdi", plaintextR);

        



        if (inputTypes==DataTypes.Hex)
        {
             plaintext = Enumerable.Range(0, plaintextR.Length)
                                     .Where(x => x % 2 == 0)
                                     .Select(x => Convert.ToByte(plaintextR.Substring(x, 2), 16))
                                     .ToArray();
        }
        else if (inputTypes == DataTypes.String)
        {
            plaintext = Encoding.UTF8.GetBytes(plaintextR);

        }
        else
        {
            
            string[] stringBytes = plaintextR.Split('-');
            plaintext = new byte[stringBytes.Length];

            for (int i = 0; i < stringBytes.Length; i++)
            {
                plaintext[i] = Convert.ToByte(stringBytes[i], 16); // Hexadecimal olarak çevirme
            }
            
        }

        ciphertext = EncryptString(plaintext, key);
        AddStep("Şifrelenmiş girdi", System.Text.Encoding.UTF8.GetString(ciphertext));


        byte[] decryptedtext = DecryptString(ciphertext, key);


        if (outputTypes == DataTypes.Hex)
        {
            
            string DEChex = BitConverter.ToString(decryptedtext).Replace("-", "");
            AddStep("şifresi çözülen mesaj:", DEChex);
            Console.WriteLine("Deşifrelenmiş girdi: " + DEChex);

        }
        else if (outputTypes == DataTypes.String)
        {
            
            string result = System.Text.Encoding.UTF8.GetString(decryptedtext);
            AddStep("şifresi çözülen mesaj:", result);
            Console.WriteLine("Deşifrelenmiş girdi: " + result);
        }
        else
        {

            string result = BitConverter.ToString(decryptedtext);
            AddStep("şifresi çözülen mesaj  :", result);
            Console.WriteLine("Deşifrelenmiş girdi: " + result);

        }


            Console.WriteLine("complated");

    }

    public byte[] Encrypt(byte[] data, byte[] key)
    {
        var keyBuffer = CreateKey(key);
        var blockBuffer = new uint[2];
        var result = new byte[NextMultipleOf8(data.Length + 4)];
        var lengthBuffer = BitConverter.GetBytes(data.Length);
        Array.Copy(lengthBuffer, result, lengthBuffer.Length);
        Array.Copy(data, 0, result, lengthBuffer.Length, data.Length);
        using (var stream = new MemoryStream(result))
        {
            using (var writer = new BinaryWriter(stream))
            {
                for (int i = 0; i < result.Length; i += 8)
                {
                    blockBuffer[0] = BitConverter.ToUInt32(result, i);
                    blockBuffer[1] = BitConverter.ToUInt32(result, i + 4);
                    Encrypt(Rounds, blockBuffer, keyBuffer);
                    string bufferX = blockBuffer[0].ToString();
                    AddStep("deşifrelenmiş blok 1 " + i / 8, bufferX);
                    bufferX = blockBuffer[1].ToString();
                    AddStep("deşifrelenmiş blok 2 " + i / 8, bufferX);
                    writer.Write(blockBuffer[0]);
                    writer.Write(blockBuffer[1]);
                }
            }
        }
        return result;
    }
    private const uint Rounds = 32;

    public  byte[] Decrypt(byte[] data, byte[] key)
    {
        if (data.Length % 8 != 0) throw new ArgumentException("Encrypted data length must be a multiple of 8 bytes.");
        var keyBuffer = CreateKey(key);
        var blockBuffer = new uint[2];
        var buffer = new byte[data.Length];
        Array.Copy(data, buffer, data.Length);
        using (var stream = new MemoryStream(buffer))
        {
            using (var writer = new BinaryWriter(stream))
            {
                for (int i = 0; i < buffer.Length; i += 8)
                {
                    blockBuffer[0] = BitConverter.ToUInt32(buffer, i);
                    blockBuffer[1] = BitConverter.ToUInt32(buffer, i + 4);
                    Decrypt(Rounds, blockBuffer, keyBuffer);
                    string bufferX = blockBuffer[0].ToString();
                    AddStep("deşifrelenmiş blok 1 " + i/8, bufferX);
                    bufferX = blockBuffer[1].ToString();
                    AddStep("deşifrelenmiş blok 2 " + i / 8, bufferX);
                    writer.Write(blockBuffer[0]);
                    writer.Write(blockBuffer[1]);
                }
            }
        }

        var length = BitConverter.ToUInt32(buffer, 0);
        if (length > buffer.Length - 4) throw new ArgumentException("Invalid encrypted data");
        var result = new byte[length];
        Array.Copy(buffer, 4, result, 0, length);
        return result;
    }

    private static int NextMultipleOf8(int length)
    {

        return (length + 7) / 8 * 8;
    }


    private static uint[] CreateKey(byte[] key)
    {

        var hash = new byte[16];
        for (int i = 0; i < key.Length; i++)
        {
            hash[i % 16] = (byte)((31 * hash[i % 16]) ^ key[i]);
        }
        for (int i = key.Length; i < hash.Length; i++)
        {
            hash[i] = (byte)(17 * i ^ key[i % key.Length]);
        }
        return new[] {
                BitConverter.ToUInt32(hash, 0), BitConverter.ToUInt32(hash, 4),
                BitConverter.ToUInt32(hash, 8), BitConverter.ToUInt32(hash, 12)
            };
    }

    

    private static void Encrypt(uint rounds, uint[] v, uint[] key)
    {
        uint v0 = v[0], v1 = v[1], sum = 0, delta = 0x9E3779B9;
        for (uint i = 0; i < rounds; i++)
        {
            v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
            sum += delta;
            v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
        }
        v[0] = v0;
        v[1] = v1;
    }

    private static void Decrypt(uint rounds, uint[] v, uint[] key)
    {
        uint v0 = v[0], v1 = v[1], delta = 0x9E3779B9, sum = delta * rounds;
        for (uint i = 0; i < rounds; i++)
        {
            v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
            sum -= delta;
            v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        }
        v[0] = v0;
        v[1] = v1;
    }


    public byte[] EncryptString(byte[] plaintextBytes, byte[] key)
    {
        byte[] encrypted_block = Encrypt(plaintextBytes, key);
        return encrypted_block;
        
    }
    public int BLOCK_SIZE = 16;

    public byte[] DecryptString(byte[] ciphertext, byte[] key)
    {
        byte[] decrypted_block = Decrypt(ciphertext, key);
        return decrypted_block;
        
    }

} 