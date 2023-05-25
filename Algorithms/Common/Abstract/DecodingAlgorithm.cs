using Algorithms.Common.DataTransferObjects;

namespace Algorithms.Common.Abstract;

/// <summary>
/// 
/// </summary>
public abstract class DecodingAlgorithm : BaseCoding
{
    protected DecodingAlgorithm(InputDto input) : base(input){}
}
