using Algorithms.Common.DataTransferObjects;
using Algorithms.Common.Enums;
using Algorithms.Common.Exceptions;
using Algorithms.Common.Services;

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
    /// <param name="message"></param>
    /// <exception cref="BusinessException"></exception>
    protected void ThrowBusinessException(string message)
    {
        throw new BusinessException(message);
    }
}