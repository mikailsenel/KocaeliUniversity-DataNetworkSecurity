using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Algorithms.Common.Exceptions;
public class InternalServerErrorProblemDetails : ProblemDetails
{
    public InternalServerErrorProblemDetails(string detail)
    {
        Status = StatusCodes.Status500InternalServerError;
        Type = "https://example.com/probs/internal";
        Title = "Internal exception";
        Detail = detail;
        Instance = "";

    }
}
