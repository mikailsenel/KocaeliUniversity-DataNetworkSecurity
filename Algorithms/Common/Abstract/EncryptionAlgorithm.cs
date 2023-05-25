using Algorithms.Common.DataTransferObjects;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Algorithms.Common.Abstract;

/// <summary>
/// 
/// </summary>
public abstract class EncryptionAlgorithm : BaseCoding
{
    /// <summary>
    /// 
    /// </summary>

    public EncryptionAlgorithm(InputDto input) : base(input) { }
}
