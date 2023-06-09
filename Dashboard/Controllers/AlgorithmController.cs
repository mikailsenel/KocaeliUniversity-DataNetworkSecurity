﻿using Algorithms;
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
    [HttpGet("/mysterion/ 256 bit (32) byte key girilmelidir.", Name = nameof(GetMysterion))]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    [ProducesResponseType(StatusCodes.Status400BadRequest, Type = typeof(BusinessProblemDetail))]
    [ProducesResponseType(StatusCodes.Status500InternalServerError, Type = typeof(InternalServerErrorProblemDetails))]
    public async Task<IActionResult> GetMysterion([FromQuery] InputDto input)
    {
        return Ok(new Mysterion(input).GetSteps());
    }

    [HttpGet("/noekeon/ 64 bit (8) byte key girilmelidir.", Name = nameof(GetNoekeon))]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    public async Task<IActionResult> GetNoekeon([FromQuery] InputDto input)
    {
        return Ok(new Noekeon(input).GetSteps());
    }

    [HttpGet("/piccolo/ 128 bit (16) byte key girilmelidir.", Name = nameof(GetPiccolo))]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    public async Task<IActionResult> GetPiccolo([FromQuery] InputDto input)
    {
        return Ok(new Piccolo(input).GetSteps());
    }

    [HttpGet("/pride/ 64 bit (8) byte key girilmelidir.", Name = nameof(GetPride))]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    public async Task<IActionResult> GetPride([FromQuery] InputDto input)
    {
        return Ok(new Pride(input).GetSteps());
    }
    [HttpGet("/present/ 64 bit (8) byte key girilmelidir.", Name = nameof(GetPresent))]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    public async Task<IActionResult> GetPresent([FromQuery] InputDto input)
    {
        return Ok(new Pride(input).GetSteps());
    }

    [HttpGet("/Xtea/ 96 bit (12) byte key girilmelidir.", Name = nameof(GetXtea))]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    public async Task<IActionResult> GetXtea([FromQuery] InputDto input)
    {
        return Ok(new Xtea(input).GetSteps());
    }

    [HttpGet("/Zorro/ 128 bit (16) byte key girilmelidir.", Name = nameof(GetZorro))]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    public async Task<IActionResult> GetZorro([FromQuery] InputDto input)
    {
        return Ok(new Zorro(input).GetSteps());
    }
    
    [HttpGet("/Speck/ 96 bit (12) byte key girilmelidir.", Name = nameof(GetSpeck))]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    public async Task<IActionResult> GetSpeck([FromQuery] InputDto input)
    {
        return Ok(new Speck(input).GetSteps());
    }

    [HttpGet("/Twine/ 128 bit (16) byte key girilmelidir.", Name = nameof(GetTwine))]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    public async Task<IActionResult> GetTwine([FromQuery] InputDto input)
    {
        return Ok(new Twine(input).GetSteps());
    }



    //// ----------------------------------------------------------------

    [HttpGet("/sea/ 48 bit (6) byte key girilmelidir.", Name = nameof(GetSea))]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    [ProducesResponseType(StatusCodes.Status400BadRequest, Type = typeof(BusinessProblemDetail))]
    [ProducesResponseType(StatusCodes.Status500InternalServerError, Type = typeof(InternalServerErrorProblemDetails))]
    public async Task<IActionResult> GetSea([FromQuery] InputDto input)
    {
        return Ok(new Sea(input).GetSteps());
    }


    [HttpGet("/simeck/ 128 bit (16) byte key girilmelidir.", Name = nameof(GetSimeck))]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    [ProducesResponseType(StatusCodes.Status400BadRequest, Type = typeof(BusinessProblemDetail))]
    [ProducesResponseType(StatusCodes.Status500InternalServerError, Type = typeof(InternalServerErrorProblemDetails))]
    public async Task<IActionResult> GetSimeck([FromQuery] InputDto input)
    {
        return Ok(new Simeck(input).GetSteps());
    }

    [HttpGet("/simon/ 128 bit (16) byte key girilmelidir.", Name = nameof(GetSimon))]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    [ProducesResponseType(StatusCodes.Status400BadRequest, Type = typeof(BusinessProblemDetail))]
    [ProducesResponseType(StatusCodes.Status500InternalServerError, Type = typeof(InternalServerErrorProblemDetails))]
    public async Task<IActionResult> GetSimon([FromQuery] InputDto input)
    {
        return Ok(new Simon(input).GetSteps());
    }

    [HttpGet("/skinny/ 128 bit (16) byte key girilmelidir.", Name = nameof(GetSkinny))]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    [ProducesResponseType(StatusCodes.Status400BadRequest, Type = typeof(BusinessProblemDetail))]
    [ProducesResponseType(StatusCodes.Status500InternalServerError, Type = typeof(InternalServerErrorProblemDetails))]
    public async Task<IActionResult> GetSkinny([FromQuery] InputDto input)
    {
        return Ok(new Skinny(input).GetSteps());
    }

    [HttpGet("/sparx/ 128 bit (16) byte key girilmelidir.", Name = nameof(GetSparx))]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    [ProducesResponseType(StatusCodes.Status400BadRequest, Type = typeof(BusinessProblemDetail))]
    [ProducesResponseType(StatusCodes.Status500InternalServerError, Type = typeof(InternalServerErrorProblemDetails))]
    public async Task<IActionResult> GetSparx([FromQuery] InputDto input)
    {
        return Ok(new Sparx(input).GetSteps());
    }


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

    [HttpGet("/rc5/", Name = nameof(GetRC512))]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    [ProducesResponseType(StatusCodes.Status400BadRequest, Type = typeof(BusinessProblemDetail))]
    [ProducesResponseType(StatusCodes.Status500InternalServerError, Type = typeof(InternalServerErrorProblemDetails))]
    public async Task<IActionResult> GetRC512([FromQuery] InputDto input)
    {
        return Ok(new RC512(input).GetSteps());
    }

    // ----------------------------------------------------------------
}
