using authorization_module.API.Data;
using authorization_module.API.Data.Entities;
using authorization_module.API.Extensions;
using authorization_module.API.Models.Identity;
using authorization_module.API.Services.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Mail;
using System.Security.Claims;
using System.Text;
using System.Web;

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

        var isEmailConfirmed = await _userManager.IsEmailConfirmedAsync(user);
        if(!isEmailConfirmed)
            return Unauthorized("Corfirm your account");
            

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

    [HttpPost("register")]
    public async Task<ActionResult<AuthResponse>> Register([FromBody] RegisterRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(request);
        }
        if (await _userManager.FindByEmailAsync(request.Email) != null)
            return BadRequest("The user with the specified email address already exists");
        var user = new ApplicationUser
        {
            Email = request.Email,
            UserName = request.Email // Use email as the username
        };

        var result = await _userManager.CreateAsync(user, request.Password);

        if (!result.Succeeded)
        {
            var exustingUser = await _userManager.FindByEmailAsync(user.Email);
            await _userManager.DeleteAsync(exustingUser);

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return BadRequest(result.Errors);
        }

        var tokenn = (await _userManager.GenerateEmailConfirmationTokenAsync(user)).Trim();
        var encodedToken = HttpUtility.UrlEncode(tokenn);
        var confirmationLink = $"{Request.Scheme}://{Request.Host}/auth/confirm-email?userId={user.Id}&token={encodedToken}";

        await SendConfirmationEmail(user.Email, confirmationLink);

        return Ok("Registration successful. Please check your email for a confirmation link.");
    }


    private async Task SendConfirmationEmail(string userEmail, string confirmationLink)
    {
        try
        {
            using (var client = new SmtpClient())
            {
                client.Host = _configuration.GetSection("Email:Host").Get<string>();
                client.Port = _configuration.GetSection("Email:Port").Get<int>();
                client.DeliveryMethod = SmtpDeliveryMethod.Network;
                client.UseDefaultCredentials = false;
                client.EnableSsl = true;
                client.Credentials = new NetworkCredential(_configuration.GetSection("Email:UserName").Get<string>(), _configuration.GetSection("Email:Password").Get<string>());
                using (var message = new MailMessage(
                    from: new MailAddress(_configuration.GetSection("Email:Address").Get<string>(), _configuration.GetSection("Email:DisplayName").Get<string>()),
                    to: new MailAddress($"{userEmail}", "Client")
                    ))
                {
                    message.IsBodyHtml = true;
                    message.Subject = "Confirm Your Email";
                    message.Body = $"<html><body><a href='{confirmationLink}'>Click here to confirm your email</a></body></html>";

                    client.Send(message);
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error sending confirmation email: {ex.Message}");
        }
    }

    [HttpGet("confirm-email")]
    public async Task<ActionResult> ConfirmEmail(string userId, string token)
    {
        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(token))
        {
            // Redirect or return an error indicating invalid parameters
            return BadRequest("Invalid email confirmation parameters");
        }
        //token = HttpUtility.UrlDecode(token);
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            // Redirect or return an error indicating user not found
            return BadRequest("User not found");
        }

        var result = await _userManager.ConfirmEmailAsync(user, token);
        if (!result.Succeeded)
        {
            // Redirect or return an error indicating failed email confirmation
            return BadRequest("Failed to confirm email");
        }

        // Redirect or return a success message indicating successful email confirmation
        return Ok("Email confirmed successfully");
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