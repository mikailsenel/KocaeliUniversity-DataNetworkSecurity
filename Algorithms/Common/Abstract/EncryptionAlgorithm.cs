using Algorithms.Common.DataTransferObjects;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Algorithms.Common.Abstract;

public abstract class EncryptionAlgorithm
{
    /// <summary>
    /// 
    /// </summary>
    private List<StepDto> _steps;

    public EncryptionAlgorithm(string text)
    {
        _steps = new List<StepDto>();
        Initial(text);
    }

    /// <summary>
    /// 
    /// </summary>
    protected abstract void Initial(string text);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="description"></param>
    /// <param name="result"></param>
    protected void AddStep(string description, string result)
    {
        if (!_steps.Any())
            _steps.Add(new StepDto(1, description, result));
        else
            _steps.Add(new StepDto(_steps.Max(x => x.StepNumber) + 1, description, result));
    }

    /// <summary>
    /// 
    /// </summary>
    /// <returns></returns>
    public List<StepDto> GetSteps()
    {
        return _steps;
    }
}
