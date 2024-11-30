using authorization_module.API.Data.Entities;
using authorization_module.API.Dtos;
using authorization_module.API.Interfaces;
using Microsoft.AspNetCore.Identity;

namespace authorization_module.API.Services;

public class AuthService(UserManager<ApplicationUser> userManager,
                          SignInManager<ApplicationUser> signInManager,
                          ITokenService tokenService,
                          IEmailService emailService,
                          IConfiguration configuration) : IAuthService
{
    private readonly UserManager<ApplicationUser> _userManager = userManager;
    private readonly SignInManager<ApplicationUser> _signInManager = signInManager;
    private readonly ITokenService _tokenService = tokenService;
    private readonly IEmailService _emailService = emailService;
    private readonly IConfiguration _configuration = configuration;

    public async Task<AuthResultDto> RegisterUserAsync(RegisterDto model)
    {
        var user = new ApplicationUser
        {
            UserName = model.UserName,
            Email = model.Email
        };

        var result = await _userManager.CreateAsync(user, model.Password);
        if (!result.Succeeded)
        {
            return new AuthResultDto(
                Succeeded: false,
                Errors: result.Errors.Select(e => e.Description).ToList()
            );
        }

        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

        var encodedToken = Uri.EscapeDataString(token);

        var confirmationUri = $"{_configuration.GetValue<string>("ConfirmationLink")}={user.Id}&token={encodedToken}";
        var emailSent = await _emailService.SendEmailAsync(user.Email, 
            "Confirm your email", 
            $"Please confirm your email by clicking the following link: {confirmationUri}");

        if (!emailSent)
        {
            return new AuthResultDto(
                Succeeded: false,
                Errors: ["Failed to send confirmation email."]
            );
        }

        return new AuthResultDto(
            Succeeded: true,
            Data: "Confirm your email");
    }

    public async Task<AuthResultDto> LoginUserAsync(LoginDto model)
    {
        var result = await _signInManager.PasswordSignInAsync(
            model.UserName, model.Password, false, lockoutOnFailure: false);

        if (!result.Succeeded)
        {
            return new AuthResultDto(
                Succeeded: false,
                Errors: ["Invalid login attempt"]
            );
        }

        var user = await _userManager.FindByNameAsync(model.UserName);
        if (user == null)
        {
            return new AuthResultDto(
                Succeeded: false,
                Errors: ["User not found"]
            );
        }

        if (!user.EmailConfirmed)
        {
            return new AuthResultDto(
                Succeeded: false,
                Errors: ["Email not confirmed"]
            );
        }


        var token = _tokenService.GenerateJwtToken(model.UserName);

        return new AuthResultDto(
            Succeeded: true,
            Data: new { message = "Login successful", token }
        );
    }

    public async Task<AuthResultDto> ConfirmEmailAsync(string userId, string token)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return new AuthResultDto
            (
                Succeeded: false,
                Errors: ["User not found"]
            );
        }

        var result = await _userManager.ConfirmEmailAsync(user, token);
        if (!result.Succeeded)
        {
            return new AuthResultDto
            (
                Succeeded: false,
                Errors: result.Errors.Select(e => e.Description).ToList()
            );
        }

        return new AuthResultDto(Succeeded: true);
    }
}



