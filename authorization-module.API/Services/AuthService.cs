using authorization_module.API.Data;
using authorization_module.API.Data.Entities;
using authorization_module.API.Dtos;
using authorization_module.API.Exceptions;
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

        await _userManager.AddToRoleAsync(user, "User");

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
        try
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

            var roles = await _userManager.GetRolesAsync(user);

            var accessToken = _tokenService.GenerateJwtToken(user.Id, user.UserName!, roles);
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
        catch (Exception ex)
        {
            throw;
        }
        
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

        var roles = await _userManager.GetRolesAsync(user);
        var newAccessToken = _tokenService.GenerateJwtToken(user.Id, user.UserName!, roles);
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

    public async Task<StringResultDto> ResendConfirmationEmailAsync(ResendConfirmationEmailRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Email))
        {
            throw new ResponseException("Email is required");
        }

        var user = await _userManager.FindByEmailAsync(request.Email.Trim())
            ?? throw new ResponseException("User not found");

        if (user.EmailConfirmed)
        {
            throw new ResponseException("Email is already confirmed");
        }

        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        var encodedToken = Uri.EscapeDataString(token);

        var confirmationUri = $"{_configuration["ConfirmationLink"]}={user.Id}&token={encodedToken}";
        var emailSent = await _emailService.SendEmailAsync(user.Email!,
            "Confirm your email",
            $"Please confirm your email by clicking the following link: {confirmationUri}");

        if (!emailSent)
        {
            throw new ResponseException("Failed to send confirmation email");
        }

        return new StringResultDto("Confirm your email");
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
            EmailConfirmed = user.EmailConfirmed,
            AvatarUrl = user.AvatarUrl
        };
    }

    public async Task<UserInfoDto> FindUserByEmailAsync(string email)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            throw new ResponseException("Email is required");
        }

        var normalizedEmail = email.Trim();
        var user = await _userManager.FindByEmailAsync(normalizedEmail)
            ?? throw new ResponseException("User not found");

        return new UserInfoDto
        {
            Id = user.Id,
            UserName = user.UserName ?? string.Empty,
            Email = user.Email ?? string.Empty,
            EmailConfirmed = user.EmailConfirmed,
            AvatarUrl = user.AvatarUrl
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

    public async Task<(IEnumerable<UserInfoDto> Users, int TotalCount)> GetUsersListAsync(int page, int pageSize, string? search = null)
    {
        var query = _userManager.Users.AsQueryable();

        if (!string.IsNullOrWhiteSpace(search))
        {
            var searchLower = search.Trim().ToLower();
            query = query.Where(u =>
                (u.Email != null && u.Email.ToLower().Contains(searchLower)) ||
                (u.UserName != null && u.UserName.ToLower().Contains(searchLower)));
        }

        var totalCount = await query.CountAsync();
        
        var users = await query
            .OrderBy(u => u.Email)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        var dtos = users.Select(u => new UserInfoDto
        {
            Id = u.Id,
            UserName = u.UserName ?? string.Empty,
            Email = u.Email ?? string.Empty,
            EmailConfirmed = u.EmailConfirmed,
            AvatarUrl = u.AvatarUrl
        }).ToList();

        return (dtos, totalCount);
    }

    /// <inheritdoc />
    public async Task<StringResultDto> AdminSetUserLockoutAsync(string userId, bool lockout)
    {
        var user = await _userManager.FindByIdAsync(userId)
            ?? throw new ResponseException("User not found");

        // Enable lockout for this user if not already enabled
        await _userManager.SetLockoutEnabledAsync(user, true);

        if (lockout)
        {
            // Lock user out until year 2100 (effectively permanent)
            await _userManager.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow.AddYears(74));
        }
        else
        {
            // Remove lockout
            await _userManager.SetLockoutEndDateAsync(user, null);
        }

        return new StringResultDto(lockout ? "User has been banned" : "User has been unbanned");
    }

    /// <inheritdoc />
    public async Task<StringResultDto> UpdateAvatarUrlAsync(string userId, string? avatarUrl)
    {
        var user = await _userManager.FindByIdAsync(userId)
            ?? throw new ResponseException("User not found");

        if (string.IsNullOrWhiteSpace(avatarUrl))
        {
            user.AvatarUrl = null;
        }
        else
        {
            var trimmed = avatarUrl.Trim();
            if (trimmed.Length > 2048)
                throw new ResponseException("Avatar URL is too long");

            if (!Uri.TryCreate(trimmed, UriKind.Absolute, out var uri)
                || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
            {
                throw new ResponseException("Avatar URL must be a valid http or https address");
            }

            user.AvatarUrl = trimmed;
        }

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

        return new StringResultDto("Avatar updated successfully");
    }
}
