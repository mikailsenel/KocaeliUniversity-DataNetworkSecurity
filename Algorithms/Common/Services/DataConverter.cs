using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace Algorithms.Common.Services;

internal class DataConverter
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
    public string ConvertIntToHex(int data)
    {
        return data.ToString("X");
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="data"></param>
    /// <returns></returns>
    public int ConvertHexToInt(string data)
    {
        return int.Parse(data, System.Globalization.NumberStyles.HexNumber);
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="data"></param>
    /// <returns></returns>
    public string ConvertHexToString(string data)
    {
        return int.Parse(data, System.Globalization.NumberStyles.HexNumber).ToString();
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="data"></param>
    /// <returns></returns>
    public string ConvertStringToHex(string data)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(data);
        return Convert.ToHexString(bytes);
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
