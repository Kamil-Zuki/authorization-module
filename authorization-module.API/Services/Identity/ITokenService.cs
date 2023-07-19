using Microsoft.AspNetCore.Identity;
using authorization_module.API.Data.Entities;

namespace authorization_module.API.Services.Identity;

public interface ITokenService
{
    string CreateToken(ApplicationUser user, List<IdentityRole<long>> role);
}