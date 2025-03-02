using authorization_module.API.Dtos;

namespace authorization_module.API.Interfaces;

public interface IAuthService
{
    Task<StringResultDto> RegisterUserAsync(UserRegistrationRequest request);
    Task<StringResultDto> LoginUserAsync(UserLoginRequest request);
    Task<StringResultDto> ConfirmEmailAsync(ConfirmEmailRequest request);
    Task<StringResultDto> ForgotPasswordAsync(string email);
    Task<StringResultDto> ResetPasswordAsync(string email, string token, string newPassword);
    Task<StringResultDto> ChangePasswordAsync(string userId, string currentPassword, string newPassword);
    Task<StringResultDto> HandleExternalLoginCallbackAsync();
    Task<TokenResultDto> RefreshTokenAsync(string refreshToken);
    Task<UserProfileDto> GetUserProfileAsync(string userId);
    Task<StringResultDto> UpdateUserProfileAsync(string userId, string username, string email);
    Task<StringResultDto> ResendConfirmationEmailAsync(string email);
}