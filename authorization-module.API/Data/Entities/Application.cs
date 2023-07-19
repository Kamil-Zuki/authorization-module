using authorization_module.API.Models;

namespace authorization_module.API.Data.Entities;

public class Application : BaseEntity
{
    public string? SampleNumber { get; set; }
    public DateTime? ReceivedAt { get; set; }
    public int CassettesCount { get; set; }
    public int FragmentCount { get; set; }

    

    

    
    public long? SampleDataId { get; set; }
    public SampleData? SampleData { get; set; }
    
    public long? UserId { get; set; }
    public ApplicationUser? User { get; set; }
}