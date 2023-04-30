using Microsoft.AspNetCore.Identity;
using Glosslore_authorization.Web.Data.Entities;

namespace Glosslore_authorization.Web.Services.Identity;

public interface ITokenService
{
    string CreateToken(ApplicationUser user, List<IdentityRole<long>> role);
}