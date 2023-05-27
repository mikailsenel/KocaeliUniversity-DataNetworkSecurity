using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace Algorithms.Common.Exceptions;

internal static class ProblemDetailsExtensions
{
    public static string AsJson(this ProblemDetails details)
    {
        return JsonConvert.SerializeObject(details);
    }
}
