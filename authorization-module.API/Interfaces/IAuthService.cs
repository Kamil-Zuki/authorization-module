using authorization_module.API.Dtos;

namespace authorization_module.API.Interfaces
{
    public interface IAuthService
    {
        Task<StringResultDto> RegisterUserAsync(RegisterDto model);
        Task<StringResultDto> LoginUserAsync(LoginDto model);
        Task<StringResultDto> ConfirmEmailAsync(string userId, string token);
    }
}
