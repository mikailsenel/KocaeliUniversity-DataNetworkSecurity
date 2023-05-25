using Algorithms.Common.DataTransferObjects;
using Algorithms.Common.Enums;
using Microsoft.AspNetCore.Mvc;

namespace Dashboard.Controllers;

public class BaseController : Controller
{
    protected InputDto GetInputDto(string key,string data, DataTypes inputType, DataTypes outputType)
    {
        return new InputDto
        {
            Data = data,
            InputTypes = inputType,
            Key = key,
            OutputTypes = outputType
        };
    }
}
