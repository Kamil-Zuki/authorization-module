using Microsoft.AspNetCore.Identity;

namespace Glosslore_authorization.Web.Data.Entities;

public class ApplicationUser : IdentityUser<long>
{
    //public string? Username { get; set; }
    public string? Name { get; set; }
    //public string? Email { get; set; }


    public string? RefreshToken { get; set; }
    public DateTime RefreshTokenExpiryTime { get; set; }
}