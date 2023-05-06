using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Algorithms.Common.DataTransferObjects;

public class StepDto
{
    public int StepNumber { get; set; }
    public string StepDescription { get; set; }
    public string StepResult { get; set; }

    public StepDto(int stepNumber, string stepDescription, string stepResult)
    {
        StepNumber = stepNumber;
        StepDescription = stepDescription;
        StepResult = stepResult;
    }
}
