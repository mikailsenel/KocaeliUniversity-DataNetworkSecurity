using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Algorithms.Common.DataTransferObjects;

public class ErrorResultDto
{
    public int StatusCode { get; set; }
    public string Message { get; set; }
}
