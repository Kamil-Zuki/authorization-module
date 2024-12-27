using authorization_module.API.Data;
using authorization_module.API.Data.Entities;
using authorization_module.API.Dtos;
using authorization_module.API.Interfaces;
using Microsoft.AspNetCore.Identity;

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


    public async Task<StringResultDto> RegisterUserAsync(RegisterDto model)
    {
        if (model.Password != model.PasswordConfirmation)
        {
            throw new ResponseException([new(){Code = 400,
                Message = "Passwords do not match"}]);
        }

        var existedUser = await _userManager.FindByEmailAsync(model.Email);
        if (existedUser != null && existedUser.EmailConfirmed)
        {
            throw new ResponseException([new(){Code = 400,
                Message = "Confirmed user with such email already exists"}]);
        }

        string userName = string.Concat("User_", Guid.NewGuid().ToString("N").AsSpan(0, 8));
        var user = new ApplicationUser
        {
            UserName = userName,
            Email = model.Email
        };

        var result = await _userManager.CreateAsync(user, model.Password);
        if (!result.Succeeded)
        {
            throw new ResponseException(
                result.Errors.Select(e => new ErrorResponseMessage()
                {
                    Code = 400,
                    Message = e.Description
                }).ToList()
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
            throw new ResponseException([new(){Code = 400,
                Message = "Failed to send confirmation email."}]);
        }

        return new StringResultDto("Confirm your email");
    }

    public async Task<StringResultDto> LoginUserAsync(LoginDto model)
    {
        var user = await _userManager.FindByEmailAsync(model.Email)
            ?? throw new ResponseException([new(){Code = 500,
                Message = "User not found"}]);

        var result = await _signInManager.PasswordSignInAsync(
            user.UserName!, model.Password, false, lockoutOnFailure: false);

        if (!result.Succeeded)
        {
            throw new ResponseException([new(){Code = 400,
                Message = "Invalid login attempt"}]);
        }


        if (!user.EmailConfirmed)
        {
            throw new ResponseException([new(){Code = 400,
                Message = "Email not confirmed"}]);
        }


        var token = _tokenService.GenerateJwtToken(user.Id);

        return new StringResultDto(token);
    }

    public async Task<StringResultDto> ConfirmEmailAsync(string userId, string token)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            throw new ResponseException([new(){Code = 400,
                Message = "User not found"}]);
        }

        var result = await _userManager.ConfirmEmailAsync(user, token);
        if (!result.Succeeded)
        {
            throw new ResponseException(
                result.Errors.Select(e => new ErrorResponseMessage()
                {
                    Code = 400,
                    Message = e.Description
                }).ToList()
            );
        }
        var notConfirmedUsers = _dbContext.ApplicationUsers.Where(x => x.EmailConfirmed == false && x.Email == user.Email);
        _dbContext.RemoveRange(notConfirmedUsers);
        await _dbContext.SaveChangesAsync();

        return new StringResultDto("Confirmation completed successfully");
    }
}



