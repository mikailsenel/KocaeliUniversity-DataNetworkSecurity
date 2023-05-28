using Algorithms;
using Algorithms.Common.DataTransferObjects;
using Algorithms.Common.Enums;
using Algorithms.Common.Exceptions;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;

namespace Dashboard.Controllers;

[ApiController]
[Route("[controller]")]
public class AlgorithmController : Controller
{
    [HttpGet("/mysterion/", Name = nameof(GetMysterion))]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    [ProducesResponseType(StatusCodes.Status400BadRequest, Type = typeof(BusinessProblemDetail))]
    [ProducesResponseType(StatusCodes.Status500InternalServerError, Type = typeof(InternalServerErrorProblemDetails))]
    public async Task<IActionResult> GetMysterion([FromQuery] InputDto input)
    {
        return Ok(new Mysterion(input).GetSteps());
    }

    [HttpGet("/noekeon/", Name = nameof(GetNoekeon))]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    public async Task<IActionResult> GetNoekeon([FromQuery] InputDto input)
    {
        return Ok(new Noekeon(input).GetSteps());
    }

    [HttpGet("/piccolo/", Name = nameof(GetPiccolo))]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    public async Task<IActionResult> GetPiccolo([FromQuery] InputDto input)
    {
        return Ok(new Piccolo(input).GetSteps());
    }

    [HttpGet("/pride/{text}", Name = nameof(GetPride))]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    public async Task<IActionResult> GetPride([FromQuery] InputDto input)
    {
        return Ok(new Pride(input).GetSteps());
    }
    [HttpGet("/present/{text}", Name = nameof(GetPresent))]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    public async Task<IActionResult> GetPresent([FromQuery] InputDto input)
    {
        return Ok(new Pride(input).GetSteps());
    }


    // [HttpGet("/sea/{text}", Name = nameof(GetSea))]
    // [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    // public async Task<IActionResult> GetSea([FromRoute] string text)
    // {
    //     return Ok(new Sea(text).GetSteps());
    // }

    // [HttpGet("/simeck/{text}", Name = nameof(GetSimeck))]
    // [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    // public async Task<IActionResult> GetSimeck([FromRoute] string text)
    // {
    //     return Ok(new Simeck(text).GetSteps());
    // }

    // [HttpGet("/simon/{text}", Name = nameof(GetSimon))]
    // [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    // public async Task<IActionResult> GetSimon([FromRoute] string text)
    // {
    //     return Ok(new Simon(text).GetSteps());
    // }

    // [HttpGet("/skinny/{text}", Name = nameof(GetSkinny))]
    // [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    // public async Task<IActionResult> GetSkinny([FromRoute] string text)
    // {
    //     return Ok(new Skinny(text).GetSteps());
    // }

    // [HttpGet("/sparx/{text}", Name = nameof(GetSparx))]
    // [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    // public async Task<IActionResult> GetSparx([FromRoute] string text)
    // {
    //     return Ok(new Sparx(text).GetSteps());
    // }

    //// ----------------------------------------------------------------

    [HttpGet("/roadrunner/", Name = nameof(GetRoadRunner))]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    [ProducesResponseType(StatusCodes.Status400BadRequest, Type = typeof(BusinessProblemDetail))]
    [ProducesResponseType(StatusCodes.Status500InternalServerError, Type = typeof(InternalServerErrorProblemDetails))]
    public async Task<IActionResult> GetRoadRunner([FromQuery] InputDto input)
    {
        return Ok(new RoadRunneR(input).GetSteps());
    }

    [HttpGet("/prince/", Name = nameof(GetPrince))]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    [ProducesResponseType(StatusCodes.Status400BadRequest, Type = typeof(BusinessProblemDetail))]
    [ProducesResponseType(StatusCodes.Status500InternalServerError, Type = typeof(InternalServerErrorProblemDetails))]
    public async Task<IActionResult> GetPrince([FromQuery] InputDto input)
    {
        return Ok(new Prince(input).GetSteps());
    }

    [HttpGet("/robin/", Name = nameof(GetRobin))]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    [ProducesResponseType(StatusCodes.Status400BadRequest, Type = typeof(BusinessProblemDetail))]
    [ProducesResponseType(StatusCodes.Status500InternalServerError, Type = typeof(InternalServerErrorProblemDetails))]
    public async Task<IActionResult> GetRobin([FromQuery] InputDto input)
    {
        return Ok(new Robin(input).GetSteps());
    }

    [HttpGet("/rectangle/", Name = nameof(GetRectangle))]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    [ProducesResponseType(StatusCodes.Status400BadRequest, Type = typeof(BusinessProblemDetail))]
    [ProducesResponseType(StatusCodes.Status500InternalServerError, Type = typeof(InternalServerErrorProblemDetails))]
    public async Task<IActionResult> GetRectangle([FromQuery] InputDto input)
    {
        return Ok(new Rectangle(input).GetSteps());
    }

    // ----------------------------------------------------------------
}
