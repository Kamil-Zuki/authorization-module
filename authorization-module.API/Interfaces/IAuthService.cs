using authorization_module.API.Dtos;

namespace authorization_module.API.Interfaces
{
    public interface IAuthService
    {
        Task<StringResultDto> RegisterUserAsync(UserRegistrationRequest request);
        Task<StringResultDto> LoginUserAsync(UserLoginRequest request);
        Task<StringResultDto> ConfirmEmailAsync(ConfirmEmailRequest request);
    }
}
