using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using authorization_module.API.Data;
using authorization_module.API.Data.Entities;
using authorization_module.API.Extensions;
using authorization_module.API.Models.Identity;
using authorization_module.API.Services.Identity;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;
using System.Text;

namespace authorization_module.API.Controllers;

[ApiController]
[Route("auth")]
public class AccountsController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly DataContext _context;
    private readonly ITokenService _tokenService;
    private readonly IConfiguration _configuration;

    public AccountsController(ITokenService tokenService, DataContext context, UserManager<ApplicationUser> userManager, IConfiguration configuration)
    {
        _tokenService = tokenService;
        _context = context;
        _userManager = userManager;
        _configuration = configuration;
    }

    [HttpPost("login")]
    public async Task<ActionResult<AuthResponse>> Authenticate([FromBody] AuthRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var managedUser = await _userManager.FindByEmailAsync(request.Email);
        
        if (managedUser == null)
        {
            return BadRequest("Bad credentials");
        }
        
        var isPasswordValid = await _userManager.CheckPasswordAsync(managedUser, request.Password);
        
        if (!isPasswordValid)
        {
            return BadRequest("Bad credentials");
        }
        
        var user = _context.Users.FirstOrDefault(u => u.Email == request.Email);
        
        if (user is null)
            return Unauthorized();

        var roleIds = await _context.UserRoles.Where(r => r.UserId == user.Id).Select(x => x.RoleId).ToListAsync();
        var roles = _context.Roles.Where(x => roleIds.Contains(x.Id)).ToList();
        
        var accessToken = _tokenService.CreateToken(user, roles);
        user.RefreshToken = _configuration.GenerateRefreshToken();
        user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(_configuration.GetSection("Jwt:RefreshTokenValidityInDays").Get<int>());

        await _context.SaveChangesAsync();
        
        return Ok(new AuthResponse
        {
            Username = user.UserName!,
            Email = user.Email!,
            Token = accessToken,
            RefreshToken = user.RefreshToken
        });
    }
    
    //[HttpPost("register")]
    //public async Task<ActionResult<AuthResponse>> Register([FromBody] RegisterRequest request)
    //{
    //    if (!ModelState.IsValid) return BadRequest(request);
        
    //    var user = new ApplicationUser
    //    {
    //        Email = request.Email, 
    //        UserName = request.UserName
    //    };
    //    var result = await _userManager.CreateAsync(user, request.Password);
    //    foreach (var error in result.Errors)
    //    {
    //        ModelState.AddModelError(string.Empty, error.Description);
    //    }

    //    if (!result.Succeeded) 
    //    {
            
    //        return BadRequest(result.Errors); 
    //    }

    //    var findUser = await _context.Users.FirstOrDefaultAsync(x => x.Email == request.Email);

    //    if (findUser == null) throw new Exception($"User {request.Email} not found");

    //    await _userManager.AddToRoleAsync(findUser, RoleConsts.Member);
            
    //    return await Authenticate(new AuthRequest
    //    {
    //        Email = request.Email,
    //        Password = request.Password
    //    });
    //}

    [HttpPost("register")]
    public async Task<ActionResult<AuthResponse>> Register([FromBody] RegisterRequest request)
    {
        if (!ModelState.IsValid) return BadRequest(request);

        var findUser = await _context.Users.FirstOrDefaultAsync(x => x.Email == request.Email);
        if (findUser != null) return BadRequest("User already exists with the given email.");

        var user = new ApplicationUser
        {
            Email = request.Email,
            UserName = request.UserName
        };

        var result = await _userManager.CreateAsync(user, request.Password);
        if (!result.Succeeded)
        {
            // Delete the user if registration fails
            await _userManager.DeleteAsync(user);

            // Return the errors
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
            return BadRequest(result.Errors);
        }

        await _userManager.AddToRoleAsync(user, RoleConsts.Member);

        var authRequest = new AuthRequest
        {
            Email = request.Email,
            Password = request.Password
        };

        return await Authenticate(new AuthRequest
        {
            Email = request.Email,
            Password = request.Password
        });
    }
    [HttpGet("external-login")]
    public IActionResult ExternalLogin(string provider)
    {
        var properties = new AuthenticationProperties
        {
            RedirectUri = "/external-login-callback"
        };

        return Challenge(properties, provider);
    }

    [HttpGet("external-login-callback")]
    public async Task<IActionResult> ExternalLoginCallback()
    {
        var authenticateResult = await HttpContext.AuthenticateAsync(IdentityConstants.ExternalScheme);

        if (!authenticateResult.Succeeded)
        {
            // Handle external authentication failure
            return BadRequest("External authentication failed.");
        }

        var externalId = authenticateResult.Principal.FindFirstValue(ClaimTypes.NameIdentifier);
        var email = authenticateResult.Principal.FindFirstValue(ClaimTypes.Email);

        // Retrieve additional user details as needed

        var user = await _userManager.FindByEmailAsync(email);

        if (user != null)
        {
            var authRequest = new AuthRequest
            {
                Email = email,
                Password = GenerateRandomPassword()
            };

            return Ok(await Authenticate(authRequest));
        }
        else
        {
            var newUser = new ApplicationUser
            {
                Email = email,
                UserName = externalId
            };

            var result = await _userManager.CreateAsync(newUser);

            if (result.Succeeded)
            {
                await _userManager.AddToRoleAsync(newUser, RoleConsts.Member);

                var authRequest = new AuthRequest
                {
                    Email = email,
                    Password = GenerateRandomPassword()
                };

                return Ok(await Authenticate(authRequest));
            }
            else
            {
                // Handle new user registration failure
                return BadRequest("User registration failed.");
            }
        }
    }

    private string GenerateRandomPassword()
    {
        const string pool = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()-_=+";
        const int length = 10;

        var random = new Random();
        var password = new StringBuilder(length);

        for (var i = 0; i < length; i++)
        {
            var characterIndex = random.Next(0, pool.Length);
            password.Append(pool[characterIndex]);
        }

        return password.ToString();

    }



        [HttpPost]
    [Route("refresh-token")]
    public async Task<IActionResult> RefreshToken(TokenModel? tokenModel)
    {
        if (tokenModel is null)
        {
            return BadRequest("Invalid client request");
        }

        var accessToken = tokenModel.AccessToken;
        var refreshToken = tokenModel.RefreshToken;
        var principal = _configuration.GetPrincipalFromExpiredToken(accessToken);
        
        if (principal == null)
        {
            return BadRequest("Invalid access token or refresh token");
        }
        
        var username = principal.Identity!.Name;
        var user = await _userManager.FindByNameAsync(username!);

        if (user == null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.UtcNow)
        {
            return BadRequest("Invalid access token or refresh token");
        }

        var newAccessToken = _configuration.CreateToken(principal.Claims.ToList());
        var newRefreshToken = _configuration.GenerateRefreshToken();

        user.RefreshToken = newRefreshToken;
        await _userManager.UpdateAsync(user);

        return new ObjectResult(new
        {
            accessToken = new JwtSecurityTokenHandler().WriteToken(newAccessToken),
            refreshToken = newRefreshToken
        });
    }
    
    [Authorize]
    [HttpPost]
    [Route("revoke/{username}")]
    public async Task<IActionResult> Revoke(string username)
    {
        var user = await _userManager.FindByNameAsync(username);
        if (user == null) return BadRequest("Invalid user name");

        user.RefreshToken = null;
        await _userManager.UpdateAsync(user);

        return Ok();
    }
    
    [Authorize]
    [HttpPost]
    [Route("revoke-all")]
    public async Task<IActionResult> RevokeAll()
    {
        var users = _userManager.Users.ToList();
        foreach (var user in users)
        {
            user.RefreshToken = null;
            await _userManager.UpdateAsync(user);
        }

        return Ok();
    }
}