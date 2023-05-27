using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Algorithms.Common.Exceptions;

public class BusinessProblemDetail : ProblemDetails
{

    public BusinessProblemDetail(string detail)
    {
        Status = StatusCodes.Status400BadRequest;
        Type = "https://example.com/probs/business";
        Title = "Business exception";
        Detail = detail;
        Instance = "";
    }
}
