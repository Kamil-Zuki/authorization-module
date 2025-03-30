using authorization_module.API.Dtos;
using authorization_module.API.Interfaces;
using FluentValidation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace authorization_module.API.Controllers
{
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
        public async Task<ActionResult<StringResultDto>> Login([FromBody] UserLoginRequest request)
        {
            var validationResult = await _userLoginValidator.ValidateAsync(request);
            if (!validationResult.IsValid)
            {
                return BadRequest(new { validationResult.Errors });
            }

            var result = await _authService.LoginUserAsync(request);
            return Ok(result);
        }

        [HttpPost("refresh-token")]
        public async Task<ActionResult<TokenDto>> RefreshToken([FromBody] RefreshTokenRequest request)
        {
            var result = await _authService.RefreshToken(request);
            return Ok(result);
        }

        [HttpGet("confirm-email")]
        public async Task<ActionResult<StringResultDto>> ConfirmEmail([FromQuery] ConfirmEmailRequest request)
        {
            var result = await _authService.ConfirmEmailAsync(request);
            return Ok(result);
        }

        [Authorize]
        [HttpGet("me")]
        public async Task<IActionResult> GetUserInfo()
        {
            var userId = GetUserIdFromToken();

            var userInfo = await _authService.GetUserInfoAsync(userId);
            return Ok(userInfo);
        }

        [Authorize]
        [HttpPost("logout")]
        public async Task<IActionResult> Logout([FromBody] string refreshToken)
        {
            var userId = GetUserIdFromToken();
            var result = await _authService.LogoutUserAsync(userId, refreshToken);
            return Ok(new { Message = result.Data });
        }

        [Authorize]
        [HttpPut("username")]
        public async Task<IActionResult> UpdateUsername([FromBody] string newUserName)
        {
            var userId = GetUserIdFromToken();
            var result = await _authService.UpdateUserNameAsync(userId, newUserName);
            return Ok(new { Message = result.Data });
        }

        [Authorize]
        [HttpPut("password")]
        public async Task<IActionResult> UpdatePassword([FromBody] UpdatePasswordRequest request)
        {
            var userId = GetUserIdFromToken();
            var result = await _authService.UpdateUserPasswordAsync(userId, request.CurrentPassword, request.NewPassword);
            return Ok(new { Message = result.Data });
        }

        private string GetUserIdFromToken() => User.FindFirst(ClaimTypes.NameIdentifier).Value ?? throw new UnauthorizedAccessException();
    }
}
