using authorization_module.API.Dtos;

namespace authorization_module.API.Interfaces
{
    public interface IAuthService
    {
        Task<StringResultDto> RegisterUserAsync(UserRegistrationRequest request);
        Task<TokenDto> LoginUserAsync(UserLoginRequest request);
        Task<TokenDto> RefreshToken(RefreshTokenRequest request);
        Task<StringResultDto> ConfirmEmailAsync(ConfirmEmailRequest request);
        Task<UserInfoDto> GetUserInfoAsync(string userId);
    }
}
