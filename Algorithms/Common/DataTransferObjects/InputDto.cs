using Algorithms.Common.Enums;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace Algorithms.Common.DataTransferObjects;

public class InputDto
{
    [Required]
    [Description("sdwd")]
    public string Key { get; set; }
    [Required]
    public string Data { get; set; }
    [Required]
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public DataTypes InputTypes { get; set; }
    [Required]
    public DataTypes OutputTypes { get; set; }
}
