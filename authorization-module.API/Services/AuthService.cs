using authorization_module.API.Data;
using authorization_module.API.Data.Entities;
using authorization_module.API.Dtos;
using authorization_module.API.Interfaces;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;
using System.Text.Json;

namespace authorization_module.API.Services;

public class AuthService : IAuthService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IEmailService _emailService;
    private readonly IConfiguration _configuration;
    private readonly DataContext _dbContext;
    private readonly IHttpClientFactory _httpClientFactory;

    public AuthService(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
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

    public async Task<TokenResultDto> LoginUserAsync(UserLoginRequest model)
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

        return await GetTokenFromIdentityServerAsync(user.UserName!, model.Password);
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

        var notConfirmedUsers = _dbContext.ApplicationUsers
            .Where(x => !x.EmailConfirmed && x.Email == user.Email);
        _dbContext.RemoveRange(notConfirmedUsers);
        await _dbContext.SaveChangesAsync();

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

    public async Task<TokenResultDto> HandleExternalLoginCallbackAsync()
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

        return await GetTokenFromIdentityServerAsync(user.UserName!, null);
    }

    public async Task<TokenResultDto> RefreshTokenAsync(string refreshToken)
    {
        var client = _httpClientFactory.CreateClient();
        var request = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("grant_type", "refresh_token"),
            new KeyValuePair<string, string>("refresh_token", refreshToken),
            new KeyValuePair<string, string>("client_id", _configuration["IdentityServer:ClientId"]),
            new KeyValuePair<string, string>("client_secret", _configuration["IdentityServer:ClientSecret"])
        });

        var response = await client.PostAsync(_configuration["IdentityServer:TokenEndpoint"], request);
        if (!response.IsSuccessStatusCode)
        {
            var errorContent = await response.Content.ReadAsStringAsync();
            throw new ResponseException($"Failed to refresh token: {response.StatusCode} - {errorContent}");
        }
        var responseContent = await response.Content.ReadAsStringAsync();
        Console.WriteLine($"Refresh token raw response content: {responseContent}");

        if (!response.IsSuccessStatusCode)
        {
            throw new ResponseException($"Failed to obtain token: {response.StatusCode} - {responseContent}");
        }

        try
        {

            Console.WriteLine(responseContent);
            return JsonSerializer.Deserialize<TokenResultDto>(responseContent);
        }
        catch (JsonException ex)
        {
            throw new ResponseException($"Invalid JSON in token response: {ex.Message} - Response: {responseContent}");
        }
        //return new TokenResultDto
        //{
        //    AccessToken = tokenData["access_token"],
        //    RefreshToken = tokenData["refresh_token"]
        //};
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

    private async Task<TokenResultDto> GetTokenFromIdentityServerAsync(string username, string? password)
    {
        var client = _httpClientFactory.CreateClient();

        var tokenEndpoint = _configuration["IdentityServer:TokenEndpoint"]
            ?? throw new InvalidOperationException("Token endpoint is not configured.");
        var clientId = _configuration["IdentityServer:ClientId"]
            ?? throw new InvalidOperationException("ClientId is not configured.");
        var clientSecret = _configuration["IdentityServer:ClientSecret"]
            ?? throw new InvalidOperationException("ClientSecret is not configured.");
        var scope = _configuration["IdentityServer:Scope"]
            ?? throw new InvalidOperationException("Scope is not configured.");

        var parameters = new List<KeyValuePair<string, string>>
        {
            new("grant_type", password != null ? "password" : "client_credentials"),
            new("client_id", clientId),
            new("client_secret", clientSecret),
            new("scope", scope)
        };

        if (password != null)
        {
            parameters.Add(new("username", username));
            parameters.Add(new("password", password));
        }

        var request = new FormUrlEncodedContent(parameters);
        var response = await client.PostAsync(tokenEndpoint, request);

        Console.WriteLine($"Response Status: {response.StatusCode}");

        var responseContent = await response.Content.ReadAsStringAsync();
        Console.WriteLine($"Raw Response Content: {responseContent}");

        if (!response.IsSuccessStatusCode)
        {
            throw new ResponseException($"Failed to obtain token: {response.StatusCode} - {responseContent}");
        }

        try
        {

            Console.WriteLine(responseContent);
            return JsonSerializer.Deserialize<TokenResultDto>(responseContent);
        }
        catch (JsonException ex)
        {
            throw new ResponseException($"Invalid JSON in token response: {ex.Message} - Response: {responseContent}");
        }
    }

}