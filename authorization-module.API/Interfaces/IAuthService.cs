using authorization_module.API.Dtos;

namespace authorization_module.API.Interfaces
{
    public interface IAuthService
    {
        Task<AuthResultDto> RegisterUserAsync(RegisterDto model);
        Task<AuthResultDto> LoginUserAsync(LoginDto model);
        Task<AuthResultDto> ConfirmEmailAsync(string userId, string token);
    }
}
