using Glosslore_authorization.Web.Models;

namespace Glosslore_authorization.Web.Data.Entities;

public class SampleData : BaseEntity
{
    public DateTime SamplingDate { get; set; }
    public string Localization { get; set; } = null!;
    public string LesionDescription { get; set; } = null!;
}