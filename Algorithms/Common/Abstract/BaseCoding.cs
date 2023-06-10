using Algorithms.Common.DataTransferObjects;
using Algorithms.Common.Enums;
using Algorithms.Common.Exceptions;
using Algorithms.Common.Services;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text;

namespace Algorithms.Common.Abstract;

/// <summary>
/// 
/// </summary>
public abstract class BaseCoding
{
    protected List<StepDto> Steps;
    protected string HexValue;
    protected string StringValue;
    protected byte[] ByteValue;

    /// <summary>
    /// 
    /// </summary>
    /// <param name="input"></param>
    public BaseCoding(InputDto input)
    {
        Steps = new List<StepDto>();
        convert(input.Data, input.InputTypes);
        Initial(input.Key, input.InputTypes, input.OutputTypes);
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="key"></param>
    /// <param name="inputTypes"></param>
    /// <param name="outputTypes"></param>
    protected abstract void Initial(string inputKey, DataTypes inputTypes, DataTypes outputTypes);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="description"></param>
    /// <param name="result"></param>
    protected void AddStep(string description, string result)
    {
        if (!Steps.Any())
            Steps.Add(new StepDto(1, description, result));
        else
            Steps.Add(new StepDto(Steps.Max(x => x.StepNumber) + 1, description, result));
    }

    /// <summary>
    /// 
    /// </summary>
    /// <returns></returns>
    public List<StepDto> GetSteps()
    {
        return Steps;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="data"></param>
    /// <param name="ınputTypes"></param>
    private void convert(string data, DataTypes inputTypes)
    {
        switch (inputTypes)
        {
            case DataTypes.String:
                StringValue = data;
                HexValue = DataConverter.Instance.ConvertStringToHex(data);
                ByteValue = DataConverter.Instance.ConvertStringToByte(data);
                break;
            case DataTypes.Hex:
                HexValue = data;
                StringValue = DataConverter.Instance.ConvertHexToString(data);
                ByteValue = DataConverter.Instance.ConvertHexToByte(StringValue);
                //HexValue doğru çalışan kısım.
                //ByteValue = DataConverter.Instance.ConvertHexToByte(HexValue);
                //StringValue = Encoding.ASCII.GetString (ByteValue);
                break;
            case DataTypes.Byte:
                ByteValue = DataConverter.Instance.ConvertStringToByte(data);
                StringValue = DataConverter.Instance.ConvertByteToString(ByteValue);
                HexValue = DataConverter.Instance.ConvertStringToHex(StringValue);
                break;
        }
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="data"></param>
    /// <param name="ınputTypes"></param>
    protected void FinalStep(string data, DataTypes sourceType, DataTypes destinationType)
    {
        string plainText = "";
        switch (sourceType)
        {
            case DataTypes.String:
                plainText = data;
                break;
            case DataTypes.Hex:
                plainText = DataConverter.Instance.ConvertHexToString(data);
                break;
            default:
                ThrowBusinessException("Beklenmeyen data tipi");
                break;
        }
        string pattern = "{0} türünde çıktı:";
        switch (destinationType)
        {
            case DataTypes.String:
                AddStep(String.Format(pattern, "Plain text"), plainText);
                break;
            case DataTypes.Hex:
                AddStep(String.Format(pattern, "Hex"), DataConverter.Instance.ConvertStringToHex(plainText));
                break;
            case DataTypes.Byte:
                AddStep(String.Format(pattern, "Byte"), DataConverter.Instance.ConvertStringToByte(plainText).ToString());
                break;
        }
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="data"></param>
    /// <param name="ınputTypes"></param>
    protected void FinalStep(byte[] data,  DataTypes destinationType)
    {
        string pattern = "{0} türünde çıktı:";
        switch (destinationType)
        {
            case DataTypes.String:
                AddStep(String.Format(pattern, "Plain text"), DataConverter.Instance.ConvertByteToString(data));
                break;
            case DataTypes.Hex:
                AddStep(String.Format(pattern, "Hex"), DataConverter.Instance.ConvertByteToHex(data));
                break;
            case DataTypes.Byte:
                AddStep(String.Format(pattern, "Byte"), DataConverter.Instance.ConvertByteToString(data));
                break;
        }
    }


    /// <summary>
    /// 
    /// </summary>
    /// <param name="message"></param>
    /// <exception cref="BusinessException"></exception>
    protected void ThrowBusinessException(string message)
    {
        throw new BusinessException(message);
    }
}