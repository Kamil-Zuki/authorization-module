using authorization_module.API.Models;

namespace authorization_module.API.Data.Entities;

public class SampleData : BaseEntity
{
    public DateTime SamplingDate { get; set; }
    public string Localization { get; set; } = null!;
    public string LesionDescription { get; set; } = null!;
}