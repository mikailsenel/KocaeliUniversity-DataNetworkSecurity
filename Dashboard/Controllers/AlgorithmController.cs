using Algorithms;
using Algorithms.Common.DataTransferObjects;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;

namespace Dashboard.Controllers;

[ApiController]
[Route("[controller]")]
public class AlgorithmController : Controller
{
    [HttpGet("/mysterion/{text}", Name = nameof(GetMysterion))]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    public async Task<IActionResult> GetMysterion([FromRoute] string text)
    {
        return Ok(new Mysterion(text).GetSteps());
    }

    [HttpGet("/noekeon/{text}", Name = nameof(GetNoekeon))]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    public async Task<IActionResult> GetNoekeon([FromRoute] string text)
    {
        return Ok(new Noekeon(text).GetSteps());
    }

    [HttpGet("/piccolo/{text}", Name = nameof(GetPiccolo))]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    public async Task<IActionResult> GetPiccolo([FromRoute] string text)
    {
        return Ok(new Piccolo(text).GetSteps());
    }

    [HttpGet("/pride/{text}", Name = nameof(GetPride))]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    public async Task<IActionResult> GetPride([FromRoute] string text)
    {
        return Ok(new Pride(text).GetSteps());
    }
    [HttpGet("/present/{text}", Name = nameof(GetPresent))]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    public async Task<IActionResult> GetPresent([FromRoute] string text)
    {
        return Ok(new Pride(text).GetSteps());
    }


}
