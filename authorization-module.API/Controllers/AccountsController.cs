using authorization_module.API.Dtos;
using authorization_module.API.Interfaces;
using FluentValidation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace authorization_module.API.Controllers;

[ApiController]
[Route("api/v1/auth")]
public class AccountsController : ControllerBase
{
    private readonly IAuthService _authService;
    private readonly IValidator<UserRegistrationRequest> _userRegistrationValidator;
    private readonly IValidator<UserLoginRequest> _userLoginValidator;

    public AccountsController(
        IAuthService authService,
        IValidator<UserRegistrationRequest> userRegistrationValidator,
        IValidator<UserLoginRequest> userLoginValidator)
    {
        _authService = authService;
        _userRegistrationValidator = userRegistrationValidator;
        _userLoginValidator = userLoginValidator;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] UserRegistrationRequest request)
    {
        var validationResult = await _userRegistrationValidator.ValidateAsync(request);
        if (!validationResult.IsValid)
        {
            return BadRequest(new { validationResult.Errors });
        }

        var result = await _authService.RegisterUserAsync(request);
        return Created(string.Empty, new { Message = result.Data });
    }

    [HttpPost("login")]
    public async Task<ActionResult<TokenResultDto>> Login([FromBody] UserLoginRequest request)
    {
        var validationResult = await _userLoginValidator.ValidateAsync(request);
        if (!validationResult.IsValid)
        {
            return BadRequest(new { validationResult.Errors });
        }

        var result = await _authService.LoginUserAsync(request);
        // Assuming result.Data is a JSON string from IdentityServer
        return Ok(result);
    }

    [HttpGet("confirm-email")]
    public async Task<IActionResult> ConfirmEmail([FromQuery] ConfirmEmailRequest request)
    {
        var result = await _authService.ConfirmEmailAsync(request);
        return Ok(new { Message = result.Data });
    }

    [HttpPost("forgot-password")]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
    {
        // Assuming a simple request DTO; add validator if needed
        var result = await _authService.ForgotPasswordAsync(request.Email);
        return Ok(new { Message = result.Data });
    }

    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
    {
        // Add validator if needed
        var result = await _authService.ResetPasswordAsync(request.Email, request.Token, request.NewPassword);
        return Ok(new { Message = result.Data });
    }

    [Authorize] // Requires JWT authentication
    [HttpPost("change-password")]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
    {
        var userId = User.FindFirst("sub")?.Value;
        if (string.IsNullOrEmpty(userId))
        {
            return Unauthorized(new { Message = "User not authenticated" });
        }

        // Add validator if needed
        var result = await _authService.ChangePasswordAsync(userId, request.CurrentPassword, request.NewPassword);
        return Ok(new { Message = result.Data });
    }

    [HttpGet("signin-external")]
    public async Task<ActionResult<TokenResultDto>> HandleExternalLoginCallback()
    {
        var result = await _authService.HandleExternalLoginCallbackAsync();

        return Ok(result);
    }

    [HttpPost("refresh")]
    public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
    {
        var result = await _authService.RefreshTokenAsync(request.RefreshToken);
        return Ok(new
        {
            result.AccessToken,
            result.RefreshToken
        });
    }

    [Authorize]
    [HttpGet("profile")]
    public async Task<IActionResult> GetUserProfile()
    {
        var userId = User.FindFirst("sub")?.Value;
        if (string.IsNullOrEmpty(userId))
        {
            return Unauthorized(new { Message = "User not authenticated" });
        }

        var result = await _authService.GetUserProfileAsync(userId);
        return Ok(new
        {
            result.Email,
            result.Username
        });
    }

    [Authorize]
    [HttpPut("profile")]
    public async Task<IActionResult> UpdateUserProfile([FromBody] UpdateProfileRequest request)
    {
        var userId = User.FindFirst("sub")?.Value;
        if (string.IsNullOrEmpty(userId))
        {
            return Unauthorized(new { Message = "User not authenticated" });
        }

        // Add validator if needed
        var result = await _authService.UpdateUserProfileAsync(userId, request.Username, request.Email);
        return Ok(new { Message = result.Data });
    }

    [HttpPost("resend-confirmation")]
    public async Task<IActionResult> ResendConfirmationEmail([FromBody] ResendConfirmationRequest request)
    {
        // Add validator if needed
        var result = await _authService.ResendConfirmationEmailAsync(request.Email);
        return Ok(new { Message = result.Data });
    }
}
