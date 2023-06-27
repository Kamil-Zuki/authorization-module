using Microsoft.AspNetCore.Identity;

namespace authorization_module.API.Data.Entities;

public class ApplicationUser : IdentityUser<long>
{
    //public string? Username { get; set; }
    public string? Name { get; set; }
    //public string? Email { get; set; }


    public string? RefreshToken { get; set; }
    public DateTime RefreshTokenExpiryTime { get; set; }
}