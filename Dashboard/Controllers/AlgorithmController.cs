﻿using Algorithms;
using Algorithms.Common.DataTransferObjects;
using Algorithms.Common.Enums;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;

namespace Dashboard.Controllers;

[ApiController]
[Route("[controller]")]
public class AlgorithmController : BaseController
{
    [HttpGet("/mysterion/", Name = nameof(GetMysterion))]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    public async Task<IActionResult> GetMysterion([FromQuery] InputDto input)
    {
        return Ok(new Mysterion(input).GetSteps());
    }

    //[HttpGet("/noekeon/{text}", Name = nameof(GetNoekeon))]
    //[ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    //public async Task<IActionResult> GetNoekeon([FromRoute] string text)
    //{
    //    return Ok(new Noekeon(text).GetSteps());
    //}

    //[HttpGet("/piccolo/{text}", Name = nameof(GetPiccolo))]
    //[ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    //public async Task<IActionResult> GetPiccolo([FromRoute] string text)
    //{
    //    return Ok(new Piccolo(text).GetSteps());
    //}

    //[HttpGet("/pride/{text}", Name = nameof(GetPride))]
    //[ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    //public async Task<IActionResult> GetPride([FromRoute] string text)
    //{
    //    return Ok(new Pride(text).GetSteps());
    //}
    //[HttpGet("/present/{text}", Name = nameof(GetPresent))]
    //[ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    //public async Task<IActionResult> GetPresent([FromRoute] string text)
    //{
    //    return Ok(new Pride(text).GetSteps());
    //}

    //[HttpGet("/sea/{text}", Name = nameof(GetSea))]
    //[ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    //public async Task<IActionResult> GetSea([FromRoute] string text)
    //{
    //    return Ok(new Sea(text).GetSteps());
    //}

    //[HttpGet("/simeck/{text}", Name = nameof(GetSimeck))]
    //[ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    //public async Task<IActionResult> GetSimeck([FromRoute] string text)
    //{
    //    return Ok(new Simeck(text).GetSteps());
    //}

    //[HttpGet("/simon/{text}", Name = nameof(GetSimon))]
    //[ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    //public async Task<IActionResult> GetSimon([FromRoute] string text)
    //{
    //    return Ok(new Simon(text).GetSteps());
    //}

    //[HttpGet("/skinny/{text}", Name = nameof(GetSkinny))]
    //[ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    //public async Task<IActionResult> GetSkinny([FromRoute] string text)
    //{
    //    return Ok(new Skinny(text).GetSteps());
    //}

    //[HttpGet("/sparx/{text}", Name = nameof(GetSparx))]
    //[ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    //public async Task<IActionResult> GetSparx([FromRoute] string text)
    //{
    //    return Ok(new Sparx(text).GetSteps());
    //}

    //// ----------------------------------------------------------------

    //[HttpGet("/roadrunner/{text}", Name = nameof(GetRoadRunner))]
    //[ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    //public async Task<IActionResult> GetRoadRunner([FromRoute] string text)
    //{
    //    return Ok(new RoadRunneR(text).GetSteps());
    //}

    //[HttpGet("/prince/{text}", Name = nameof(GetPrince))]
    //[ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    //public async Task<IActionResult> GetPrince([FromRoute] string text)
    //{
    //    return Ok(new Prince(text).GetSteps());
    //}

    //[HttpGet("/robin/{text}", Name = nameof(GetRobin))]
    //[ProducesResponseType(StatusCodes.Status200OK, Type = typeof(StepDto[]))]
    //public async Task<IActionResult> GetRobin([FromRoute] string text,[FromRoute] DataTypes inputType, [FromRoute] DataTypes outputType)
    //{
    //    return Ok(new Robin(text).GetSteps());
    //}

    // ----------------------------------------------------------------
}
