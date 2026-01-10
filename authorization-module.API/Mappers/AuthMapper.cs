using authorization_module.API.Dtos;
using Pvs.Auth.Grpc;
using Riok.Mapperly.Abstractions;
using GrpcRegisterUserRequest = Pvs.Auth.Grpc.RegisterUserRequest;
using GrpcLoginUserRequest = Pvs.Auth.Grpc.LoginUserRequest;
using GrpcRefreshTokenRequest = Pvs.Auth.Grpc.RefreshTokenRequest;
using GrpcConfirmEmailRequest = Pvs.Auth.Grpc.ConfirmEmailRequest;
using DtoRefreshTokenRequest = authorization_module.API.Dtos.RefreshTokenRequest;
using DtoConfirmEmailRequest = authorization_module.API.Dtos.ConfirmEmailRequest;
using DtoUserRegistrationRequest = authorization_module.API.Dtos.UserRegistrationRequest;
using DtoUserLoginRequest = authorization_module.API.Dtos.UserLoginRequest;

namespace authorization_module.API.Mappers;

/// <summary>
/// Маппер для преобразования между gRPC сообщениями и DTO для авторизации
/// </summary>
[Mapper]
public static partial class AuthMapper
{
    /// <summary>
    /// Преобразует RegisterUserRequest (gRPC) в UserRegistrationRequest (DTO)
    /// Mapperly автоматически маппит Email, Password, ConfirmPassword (одинаковые имена)
    /// </summary>
    public static partial DtoUserRegistrationRequest ToRegistrationRequest(GrpcRegisterUserRequest request);

    /// <summary>
    /// Преобразует RegisterUserResponse (DTO) в RegisterUserResponse (gRPC)
    /// Преобразует Data в Message
    /// </summary>
    [MapProperty(nameof(StringResultDto.Data), nameof(RegisterUserResponse.Message))]
    public static partial RegisterUserResponse ToGrpcResponse(StringResultDto dto);

    /// <summary>
    /// Преобразует LoginUserRequest (gRPC) в UserLoginRequest (DTO)
    /// Mapperly автоматически маппит Email, Password (одинаковые имена)
    /// </summary>
    public static partial DtoUserLoginRequest ToLoginRequest(GrpcLoginUserRequest request);

    /// <summary>
    /// Преобразует TokenDto (DTO) в TokenResponse (gRPC)
    /// Mapperly автоматически маппит AccessToken, RefreshToken (одинаковые имена)
    /// </summary>
    public static partial TokenResponse ToTokenResponse(TokenDto dto);

    /// <summary>
    /// Преобразует RefreshTokenRequest (gRPC) в RefreshTokenRequest (DTO)
    /// Mapperly автоматически маппит RefreshToken (одинаковое имя)
    /// </summary>
    public static partial DtoRefreshTokenRequest ToRefreshTokenRequest(GrpcRefreshTokenRequest request);

    /// <summary>
    /// Преобразует ConfirmEmailRequest (gRPC) в ConfirmEmailRequest (DTO)
    /// Mapperly автоматически маппит UserId, Token (одинаковые имена)
    /// </summary>
    public static partial DtoConfirmEmailRequest ToConfirmEmailRequest(GrpcConfirmEmailRequest request);

    /// <summary>
    /// Преобразует MessageResponse (DTO) в MessageResponse (gRPC)
    /// Преобразует Data в Message
    /// </summary>
    [MapProperty(nameof(StringResultDto.Data), nameof(MessageResponse.Message))]
    public static partial MessageResponse ToMessageResponse(StringResultDto dto);

    /// <summary>
    /// Преобразует UserInfoDto (DTO) в UserInfoResponse (gRPC)
    /// Mapperly автоматически маппит Id, Email, UserName, EmailConfirmed (имена совпадают в C# после генерации из proto)
    /// </summary>
    public static partial UserInfoResponse ToUserInfoResponse(UserInfoDto dto);
}
#pragma warning disable CS8795
#pragma warning restore CS8795
