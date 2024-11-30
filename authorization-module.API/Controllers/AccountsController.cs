using authorization_module.API.Dtos;
using authorization_module.API.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace authorization_module.API.Controllers
{
    [ApiController]
    [Route("api/v1/auth")]
    public class AccountsController(IAuthService authService)
        : ControllerBase
    {
        private readonly IAuthService _authService = authService;

        [HttpPost("register")]
        public async Task<ActionResult<AuthResultDto>> Register([FromBody] RegisterDto model)
        {
            var result = await _authService.RegisterUserAsync(model);

            if (result.Succeeded)
            {
                return Ok(result);
            }

            return BadRequest(result);
        }

        [HttpPost("login")]
        public async Task<ActionResult<AuthResultDto>> Login([FromBody] LoginDto model)
        {
            var result = await _authService.LoginUserAsync(model);

            if (result.Succeeded)
            {
                return Ok(result);
            }

            return Unauthorized(result);
        }

        [HttpGet("confirm-email")]
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            var result = await _authService.ConfirmEmailAsync(userId, token);

            if (result.Succeeded)
            {
                return Ok(new { message = "Email confirmed successfully." });
            }

            return BadRequest(result);
        }
    }
}
