using authorization_module.API.Dtos;

namespace authorization_module.API.Interfaces
{
    public interface IAuthService
    {
        Task<StringResultDto> RegisterUserAsync(UserRegistrationRequest request);
        Task<TokenDto> LoginUserAsync(UserLoginRequest request);
        Task<TokenDto> RefreshToken(RefreshTokenRequest request);
        Task<StringResultDto> ConfirmEmailAsync(ConfirmEmailRequest request);
        Task<StringResultDto> ResendConfirmationEmailAsync(ResendConfirmationEmailRequest request);
        Task<UserInfoDto> GetUserInfoAsync(string userId);
        Task<UserInfoDto> FindUserByEmailAsync(string email);
        Task<StringResultDto> LogoutUserAsync(string userId, string refreshToken);
        Task<StringResultDto> UpdateUserNameAsync(string userId, string newUserName);
        Task<StringResultDto> UpdateUserPasswordAsync(string userId, string currentPassword, string newPassword);
        Task<StringResultDto> UpdateAvatarUrlAsync(string userId, string? avatarUrl);
        Task<(IEnumerable<UserInfoDto> Users, int TotalCount)> GetUsersListAsync(int page, int pageSize, string? search = null);
        Task<StringResultDto> AdminSetUserLockoutAsync(string userId, bool lockout);
    }
}
    
