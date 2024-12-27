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
        public async Task<ActionResult<StringResultDto>> Register([FromBody] RegisterDto model)
        {
            try
            {
                return await _authService.RegisterUserAsync(model);
            }
            catch (ResponseException ex)
            {
                return BadRequest(new
                {
                    ex.Errors
                });
            }
            catch (Exception)
            {
                throw;
            }
        }

        [HttpPost("login")]
        public async Task<ActionResult<StringResultDto>> Login([FromBody] LoginDto model)
        {
            try
            {
                return await _authService.LoginUserAsync(model);
            }
            catch (ResponseException ex)
            {
                return BadRequest(new
                {
                    ex.Errors
                });
            }
            catch (Exception)
            {
                throw;
            }
            //return Unauthorized(result);
        }

        [HttpGet("confirm-email")]
        public async Task<ActionResult<StringResultDto>> ConfirmEmail(string userId, string token)
        {
            try
            {
                return await _authService.ConfirmEmailAsync(userId, token);
            }
            catch (ResponseException ex)
            {
                return BadRequest(new
                {
                    ex.Errors
                });
            }
            catch (Exception)
            {
                throw;
            }
        }
    }
}
