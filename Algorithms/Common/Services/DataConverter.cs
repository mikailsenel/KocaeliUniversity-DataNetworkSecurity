using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace Algorithms.Common.Services;

public class DataConverter
{
    private static readonly Lazy<DataConverter> obj = new Lazy<DataConverter>(() => new DataConverter());
    public static DataConverter Instance
    {
        get
        {
            return obj.Value;
        }
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="data"></param>
    /// <returns></returns>
    public string ConvertByteToString(byte[] data)
    {
        return BitConverter.ToString(data);
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="data"></param>
    /// <returns></returns>
    public byte[] ConvertStringToByte(string data)
    {
        return Encoding.ASCII.GetBytes(data);
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="data"></param>
    /// <returns></returns>
    public string ConvertHexToString(string data)
    {
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < data.Length; i++)
        {
            stringBuilder.Append(int.Parse(data.Substring(i, 1), System.Globalization.NumberStyles.HexNumber));

        }
        return stringBuilder.ToString();
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="data"></param>
    /// <returns></returns>
    public string ConvertStringToHex(string data)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(data);
        return Convert.ToHexString(bytes);
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="data"></param>
    /// <returns></returns>
    public string ConvertByteToHex(byte[] data)
    {
        return Convert.ToHexString(data);
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="data"></param>
    /// <returns></returns>
    public byte[] ConvertHexToByte(string data)
    {
        return Enumerable.Range(0, data.Length)
                    .Where(x => x % 2 == 0)
                    .Select(x => Convert.ToByte(data.Substring(x, 2), 16))
                    .ToArray();
    }
}
