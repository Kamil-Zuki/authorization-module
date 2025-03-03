using authorization_module.API.Data;
using authorization_module.API.Data.Entities;
using authorization_module.API.Dtos;
using authorization_module.API.Interfaces;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace authorization_module.API.Services;

public class AuthService : IAuthService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IEmailService _emailService;
    private readonly IConfiguration _configuration;
    private readonly DataContext _dbContext;
    private readonly IHttpClientFactory _httpClientFactory; // For calling IdentityServer token endpoint

    public AuthService(UserManager<ApplicationUser> userManager,
                       SignInManager<ApplicationUser> signInManager,
                       ITokenService tokenService,
                       IEmailService emailService,
                       IConfiguration configuration,
                       DataContext dbContext,
                       IHttpClientFactory httpClientFactory)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _emailService = emailService;
        _configuration = configuration;
        _dbContext = dbContext;
        _httpClientFactory = httpClientFactory;
    }

    public async Task<StringResultDto> RegisterUserAsync(UserRegistrationRequest model)
    {
        var existedUser = await _userManager.FindByEmailAsync(model.Email);
        if (existedUser != null && existedUser.EmailConfirmed)
        {
            throw new ResponseException("Confirmed user with such email already exists");
        }

        string userName = $"User_{Guid.NewGuid():N}"[..8];
        var user = new ApplicationUser
        {
            UserName = userName,
            Email = model.Email
        };

        var result = await _userManager.CreateAsync(user, model.Password);
        if (!result.Succeeded)
        {
            throw new ResponseException(
                result.Errors.Select(e => new ErrorResponseMessage
                {
                    StatusCode = 400,
                    ErrorMessage = e.Description
                }).ToList()
            );
        }

        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        var encodedToken = Uri.EscapeDataString(token);

        var confirmationUri = $"{_configuration["ConfirmationLink"]}={user.Id}&token={encodedToken}";
        var emailSent = await _emailService.SendEmailAsync(user.Email,
            "Confirm your email",
            $"Please confirm your email by clicking the following link: {confirmationUri}");

        if (!emailSent)
        {
            throw new ResponseException("Failed to send confirmation email");
        }

        return new StringResultDto("Confirm your email");
    }

    public async Task<StringResultDto> LoginUserAsync(UserLoginRequest model)
    {
        var user = await _userManager.FindByEmailAsync(model.Email)
            ?? throw new ResponseException("User not found");

        var result = await _signInManager.PasswordSignInAsync(
            user.UserName!, model.Password, false, lockoutOnFailure: false);

        if (!result.Succeeded)
        {
            throw new ResponseException("Invalid login attempt");
        }

        if (!user.EmailConfirmed)
        {
            throw new ResponseException("Email not confirmed");
        }

        // Call IdentityServer token endpoint
        var tokenResponse = await GetTokenFromIdentityServerAsync(user.UserName!, model.Password);
        return new StringResultDto(tokenResponse); // Contains access_token and refresh_token
    }

    public async Task<StringResultDto> ConfirmEmailAsync(ConfirmEmailRequest request)
    {
        var user = await _userManager.FindByIdAsync(request.UserId)
            ?? throw new ResponseException("User not found");

        var result = await _userManager.ConfirmEmailAsync(user, request.Token);
        if (!result.Succeeded)
        {
            throw new ResponseException(
                result.Errors.Select(e => new ErrorResponseMessage
                {
                    StatusCode = 400,
                    ErrorMessage = e.Description
                }).ToList()
            );
        }

        //var notConfirmedUsers = _dbContext.ApplicationUsers
        //    .Where(x => !x.EmailConfirmed && x.Email == user.Email);
        //_dbContext.RemoveRange(notConfirmedUsers);
        //await _dbContext.SaveChangesAsync();

        return new StringResultDto("Confirmation completed successfully");
    }

    public async Task<StringResultDto> ForgotPasswordAsync(string email)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null || !await _userManager.IsEmailConfirmedAsync(user))
        {
            return new StringResultDto("If the email exists, a reset link has been sent");
        }

        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        var encodedToken = Uri.EscapeDataString(token);
        var resetUri = $"{_configuration["ResetPasswordLink"]}={user.Id}&token={encodedToken}";
        var emailSent = await _emailService.SendEmailAsync(user.Email,
            "Reset your password",
            $"Reset your password by clicking this link: {resetUri}");

        if (!emailSent)
        {
            throw new ResponseException("Failed to send reset email");
        }

        return new StringResultDto("If the email exists, a reset link has been sent");
    }

    public async Task<StringResultDto> ResetPasswordAsync(string email, string token, string newPassword)
    {
        var user = await _userManager.FindByEmailAsync(email)
            ?? throw new ResponseException("Invalid email");

        var result = await _userManager.ResetPasswordAsync(user, token, newPassword);
        if (!result.Succeeded)
        {
            throw new ResponseException(
                result.Errors.Select(e => new ErrorResponseMessage
                {
                    StatusCode = 400,
                    ErrorMessage = e.Description
                }).ToList()
            );
        }

        return new StringResultDto("Password reset successfully");
    }

    public async Task<StringResultDto> ChangePasswordAsync(string userId, string currentPassword, string newPassword)
    {
        var user = await _userManager.FindByIdAsync(userId)
            ?? throw new ResponseException("User not found");

        var result = await _userManager.ChangePasswordAsync(user, currentPassword, newPassword);
        if (!result.Succeeded)
        {
            throw new ResponseException(
                result.Errors.Select(e => new ErrorResponseMessage
                {
                    StatusCode = 400,
                    ErrorMessage = e.Description
                }).ToList()
            );
        }

        return new StringResultDto("Password changed successfully");
    }

    public async Task<StringResultDto> HandleExternalLoginCallbackAsync()
    {
        var info = await _signInManager.GetExternalLoginInfoAsync();
        if (info == null)
        {
            throw new ResponseException("External authentication failed");
        }

        var user = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
        if (user == null)
        {
            var email = info.Principal.FindFirstValue(ClaimTypes.Email);
            user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                user = new ApplicationUser
                {
                    UserName = $"User_{Guid.NewGuid():N}"[..8],
                    Email = email,
                    EmailConfirmed = true
                };
                var createResult = await _userManager.CreateAsync(user);
                if (!createResult.Succeeded)
                {
                    throw new ResponseException("Failed to create user from external login");
                }
            }
            await _userManager.AddLoginAsync(user, info);
        }

        // Call IdentityServer token endpoint (use client credentials or external login flow)
        var tokenResponse = await GetTokenFromIdentityServerAsync(user.UserName!, null); // Adjust for external login
        return new StringResultDto(tokenResponse);
    }

    public async Task<TokenResultDto> RefreshTokenAsync(string refreshToken)
    {
        var client = _httpClientFactory.CreateClient();
        var response = await client.PostAsync(_configuration["IdentityServer:TokenEndpoint"], new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("grant_type", "refresh_token"),
            new KeyValuePair<string, string>("refresh_token", refreshToken),
            new KeyValuePair<string, string>("client_id", "your-client-id"),
            new KeyValuePair<string, string>("client_secret", "your-secret")
        }));

        if (!response.IsSuccessStatusCode)
        {
            throw new ResponseException("Failed to refresh token");
        }

        var json = await response.Content.ReadAsStringAsync();
        var tokenData = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(json);
        return new TokenResultDto
        {
            AccessToken = tokenData["access_token"],
            RefreshToken = tokenData["refresh_token"]
        };
    }

    public async Task<UserProfileDto> GetUserProfileAsync(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId)
            ?? throw new ResponseException("User not found");

        return new UserProfileDto
        {
            Email = user.Email,
            Username = user.UserName
        };
    }

    public async Task<StringResultDto> UpdateUserProfileAsync(string userId, string username, string email)
    {
        var user = await _userManager.FindByIdAsync(userId)
            ?? throw new ResponseException("User not found");

        var originalEmail = user.Email;
        user.UserName = username;
        user.Email = email;
        var result = await _userManager.UpdateAsync(user);
        if (!result.Succeeded)
        {
            throw new ResponseException(
                result.Errors.Select(e => new ErrorResponseMessage
                {
                    StatusCode = 400,
                    ErrorMessage = e.Description
                }).ToList()
            );
        }

        if (email != originalEmail && !user.EmailConfirmed)
        {
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var encodedToken = Uri.EscapeDataString(token);
            var confirmationUri = $"{_configuration["ConfirmationLink"]}={user.Id}&token={encodedToken}";
            await _emailService.SendEmailAsync(user.Email,
                "Confirm your new email",
                $"Please confirm your new email by clicking: {confirmationUri}");
        }

        return new StringResultDto("Profile updated successfully");
    }

    public async Task<StringResultDto> ResendConfirmationEmailAsync(string email)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null || await _userManager.IsEmailConfirmedAsync(user))
        {
            return new StringResultDto("If the email exists and is unconfirmed, a new link has been sent");
        }

        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        var encodedToken = Uri.EscapeDataString(token);
        var confirmationUri = $"{_configuration["ConfirmationLink"]}={user.Id}&token={encodedToken}";
        var emailSent = await _emailService.SendEmailAsync(user.Email,
            "Confirm your email",
            $"Please confirm your email by clicking: {confirmationUri}");

        if (!emailSent)
        {
            throw new ResponseException("Failed to send confirmation email");
        }

        return new StringResultDto("If the email exists and is unconfirmed, a new link has been sent");
    }

    // Helper Method to Call IdentityServer Token Endpoint
    private async Task<string> GetTokenFromIdentityServerAsync(string username, string? password)
    {
        var client = _httpClientFactory.CreateClient();
        var request = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("grant_type", password != null ? "password" : "client_credentials"), // Adjust for external login
            new KeyValuePair<string, string>("username", username),
            new KeyValuePair<string, string>("password", password ?? string.Empty),
            new KeyValuePair<string, string>("client_id", "your-client-id"),
            new KeyValuePair<string, string>("client_secret", "your-secret"),
            new KeyValuePair<string, string>("scope", "api1 offline_access")
        });

        var response = await client.PostAsync(_configuration["IdentityServer:TokenEndpoint"], request);
        if (!response.IsSuccessStatusCode)
        {
            throw new ResponseException("Failed to obtain token from IdentityServer");
        }

        return await response.Content.ReadAsStringAsync(); // Returns JSON with access_token, refresh_token, etc.
    }

    // Removed custom token helpers since IdentityServer handles them
}