using authorization_module.API.Data;
using authorization_module.API.Data.Entities;
using authorization_module.API.Dtos;
using authorization_module.API.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace authorization_module.API.Services;

public class AuthService(UserManager<ApplicationUser> userManager,
                          SignInManager<ApplicationUser> signInManager,
                          ITokenService tokenService,
                          IEmailService emailService,
                          IConfiguration configuration,
                          DataContext dbContext) : IAuthService
{
    private readonly UserManager<ApplicationUser> _userManager = userManager;
    private readonly SignInManager<ApplicationUser> _signInManager = signInManager;
    private readonly ITokenService _tokenService = tokenService;
    private readonly IEmailService _emailService = emailService;
    private readonly IConfiguration _configuration = configuration;
    private readonly DataContext _dbContext = dbContext;

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

    public async Task<TokenDto> LoginUserAsync(UserLoginRequest model)
    {
        var user = await _userManager.FindByEmailAsync(model.Email)
            ?? throw new ResponseException("User not found");

        var result = await _signInManager.PasswordSignInAsync(user.UserName!, model.Password, false, lockoutOnFailure: false);

        if (!result.Succeeded)
        {
            throw new ResponseException("Invalid login attempt");
        }

        if (!user.EmailConfirmed)
        {
            throw new ResponseException("Email not confirmed");
        }

        var accessToken = _tokenService.GenerateJwtToken(user.Id, user.UserName!);
        var refreshToken = _tokenService.GenerateRefreshToken();

        // Add the new refresh token without revoking existing ones
        var refreshTokenEntity = new RefreshToken
        {
            Token = refreshToken,
            UserId = user.Id,
            ExpiryDate = DateTime.UtcNow.AddDays(7),
            IsRevoked = false
        };

        _dbContext.RefreshTokens.Add(refreshTokenEntity);
        await _dbContext.SaveChangesAsync();

        return new TokenDto
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken
        };
    }

    public async Task<TokenDto> RefreshToken(RefreshTokenRequest request)
    {
        var storedToken = await _dbContext.RefreshTokens
            .FirstOrDefaultAsync(t => t.Token == request.RefreshToken);

        if (storedToken == null || storedToken.IsRevoked || storedToken.ExpiryDate < DateTime.UtcNow)
        {
            throw new ResponseException("Invalid or expired refresh token");
        }

        var user = await _userManager.FindByIdAsync(storedToken.UserId)
            ?? throw new ResponseException("User not found");

        var newAccessToken = _tokenService.GenerateJwtToken(user.Id, user.UserName!);
        var newRefreshToken = _tokenService.GenerateRefreshToken();

        // Invalidate old refresh token
        storedToken.IsRevoked = true;

        // Store new refresh token
        var newRefreshTokenEntity = new RefreshToken
        {
            Token = newRefreshToken,
            UserId = user.Id,
            ExpiryDate = DateTime.UtcNow.AddDays(7),
            IsRevoked = false
        };

        _dbContext.RefreshTokens.Add(newRefreshTokenEntity);
        await _dbContext.SaveChangesAsync();

        return new TokenDto
        {
            AccessToken = newAccessToken,
            RefreshToken = newRefreshToken
        };
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

    public async Task<UserInfoDto> GetUserInfoAsync(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId)
            ?? throw new ResponseException("User not found");

        return new UserInfoDto
        {
            Id = user.Id,
            UserName = user.UserName ?? string.Empty,
            Email = user.Email ?? string.Empty,
            EmailConfirmed = user.EmailConfirmed
        };
    }

    public async Task<StringResultDto> LogoutUserAsync(string userId, string refreshToken)
    {
        var user = await _userManager.FindByIdAsync(userId)
            ?? throw new ResponseException("User not found");

        await _signInManager.SignOutAsync();

        if (!string.IsNullOrEmpty(refreshToken))
        {
            var storedToken = await _dbContext.RefreshTokens
                .FirstOrDefaultAsync(t => t.Token == refreshToken && t.UserId == userId);

            if (storedToken != null && !storedToken.IsRevoked)
            {
                storedToken.IsRevoked = true;
                await _dbContext.SaveChangesAsync();
            }
        }

        return new StringResultDto("Logout successful");
    }

    public async Task<StringResultDto> UpdateUserNameAsync(string userId, string newUserName)
    {
        if (string.IsNullOrWhiteSpace(newUserName))
            throw new ResponseException("Username cannot be empty");

        var user = await _userManager.FindByIdAsync(userId)
            ?? throw new ResponseException("User not found");

        var existingUser = await _userManager.FindByNameAsync(newUserName);
        if (existingUser != null && existingUser.Id != userId)
            throw new ResponseException("Username is already taken");

        user.UserName = newUserName;
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

        return new StringResultDto("Username updated successfully");
    }

    public async Task<StringResultDto> UpdateUserPasswordAsync(string userId, string currentPassword, string newPassword)
    {
        if (string.IsNullOrWhiteSpace(newPassword))
            throw new ResponseException("New password cannot be empty");

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

        return new StringResultDto("Password updated successfully");
    }
}

