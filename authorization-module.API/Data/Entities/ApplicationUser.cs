using Microsoft.AspNetCore.Identity;

namespace authorization_module.API.Data.Entities;

public class ApplicationUser : IdentityUser
{
    public string? RefreshToken { get; set; }
    public DateTime RefreshTokenExpiryTime { get; set; }
}

