using AutoMapper;
using authorization_module.API.Dtos;
using authorization_module.API.Helpers;
using authorization_module.API.Interfaces;
using FluentValidation;
using Grpc.Core;
using Pvs.Auth.Grpc;
using static Pvs.Auth.Grpc.AuthService;
using GrpcRefreshTokenRequest = Pvs.Auth.Grpc.RefreshTokenRequest;
using GrpcConfirmEmailRequest = Pvs.Auth.Grpc.ConfirmEmailRequest;
using GrpcUpdateUsernameRequest = Pvs.Auth.Grpc.UpdateUsernameRequest;
using GrpcUpdatePasswordRequest = Pvs.Auth.Grpc.UpdatePasswordRequest;
using GrpcUpdateAvatarUrlRequest = Pvs.Auth.Grpc.UpdateAvatarUrlRequest;
using GrpcResendConfirmationEmailRequest = Pvs.Auth.Grpc.ResendConfirmationEmailRequest;
using DtoRefreshTokenRequest = authorization_module.API.Dtos.RefreshTokenRequest;
using DtoConfirmEmailRequest = authorization_module.API.Dtos.ConfirmEmailRequest;
using DtoResendConfirmationEmailRequest = authorization_module.API.Dtos.ResendConfirmationEmailRequest;

namespace authorization_module.API.Api.Grpc;

/// <summary>
/// gRPC сервис для работы с авторизацией
/// </summary>
public class AuthService : AuthServiceBase
{
    private readonly ILogger<AuthService> _logger;
    private readonly IAuthService _authService;
    private readonly IValidator<UserRegistrationRequest> _userRegistrationValidator;
    private readonly IValidator<UserLoginRequest> _userLoginValidator;
    private readonly IMapper _mapper;

    public AuthService(
        ILogger<AuthService> logger,
        IAuthService authService,
        IValidator<UserRegistrationRequest> userRegistrationValidator,
        IValidator<UserLoginRequest> userLoginValidator,
        IMapper mapper)
    {
        _logger = logger;
        _authService = authService;
        _userRegistrationValidator = userRegistrationValidator;
        _userLoginValidator = userLoginValidator;
        _mapper = mapper;
    }

    /// <summary>
    /// Регистрация нового пользователя
    /// </summary>
    public override async Task<RegisterUserResponse> RegisterUser(
        RegisterUserRequest request,
        ServerCallContext context)
    {
        try
        {
            _logger.LogInformation("RegisterUser gRPC request for email: {Email}", request.Email);

            // Преобразуем gRPC запрос в DTO
            var registrationDto = _mapper.Map<UserRegistrationRequest>(request);

            // Валидация с помощью FluentValidation
            var validationResult = await _userRegistrationValidator.ValidateAsync(registrationDto, context.CancellationToken);
            if (!validationResult.IsValid)
            {
                var errors = string.Join("; ", validationResult.Errors.Select(e => e.ErrorMessage));
                throw new RpcException(
                    new Status(StatusCode.InvalidArgument, $"Validation failed: {errors}"));
            }

            // Регистрация пользователя
            var result = await _authService.RegisterUserAsync(registrationDto);

            // Преобразуем DTO ответ в gRPC ответ
            var response = _mapper.Map<RegisterUserResponse>(result);

            _logger.LogInformation("User registered successfully: {Email}", request.Email);

            return response;
        }
        catch (RpcException)
        {
            throw;
        }
        catch (authorization_module.API.Exceptions.ResponseException ex)
        {
            _logger.LogWarning(ex, "Response exception during registration: {Email}", request.Email);
            throw new RpcException(
                new Status(StatusCode.InvalidArgument, ex.Message));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during registration: {Email}", request.Email);
            throw new RpcException(
                new Status(StatusCode.Internal, "Internal server error occurred"));
        }
    }

    /// <summary>
    /// Вход пользователя
    /// </summary>
    public override async Task<TokenResponse> LoginUser(
        LoginUserRequest request,
        ServerCallContext context)
    {
        try
        {
            _logger.LogInformation("LoginUser gRPC request for email: {Email}", request.Email);

            // Преобразуем gRPC запрос в DTO
            var loginDto = _mapper.Map<UserLoginRequest>(request);

            // Валидация с помощью FluentValidation
            var validationResult = await _userLoginValidator.ValidateAsync(loginDto, context.CancellationToken);
            if (!validationResult.IsValid)
            {
                var errors = string.Join("; ", validationResult.Errors.Select(e => e.ErrorMessage));
                throw new RpcException(
                    new Status(StatusCode.InvalidArgument, $"Validation failed: {errors}"));
            }

            // Вход пользователя
            var result = await _authService.LoginUserAsync(loginDto);

            // Преобразуем DTO ответ в gRPC ответ
            var response = _mapper.Map<TokenResponse>(result);

            _logger.LogInformation("User logged in successfully: {Email}", request.Email);

            return response;
        }
        catch (RpcException)
        {
            throw;
        }
        catch (authorization_module.API.Exceptions.ResponseException ex)
        {
            _logger.LogWarning(ex, "Response exception during login: {Email}", request.Email);
            
            if (ex.Message.Contains("not found") || ex.Message.Contains("Invalid login"))
            {
                throw new RpcException(
                    new Status(StatusCode.Unauthenticated, ex.Message));
            }
            
            throw new RpcException(
                new Status(StatusCode.InvalidArgument, ex.Message));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during login: {Email}", request.Email);
            throw new RpcException(
                new Status(StatusCode.Internal, "Internal server error occurred"));
        }
    }

    /// <summary>
    /// Обновление токена
    /// </summary>
    public override async Task<TokenResponse> RefreshToken(
        GrpcRefreshTokenRequest request,
        ServerCallContext context)
    {
        try
        {
            _logger.LogInformation("RefreshToken gRPC request");

            // Преобразуем gRPC запрос в DTO
            var refreshTokenDto = _mapper.Map<DtoRefreshTokenRequest>(request);

            // Обновление токена
            var result = await _authService.RefreshToken(refreshTokenDto);

            // Преобразуем DTO ответ в gRPC ответ
            var response = _mapper.Map<TokenResponse>(result);

            _logger.LogInformation("Token refreshed successfully");

            return response;
        }
        catch (RpcException)
        {
            throw;
        }
        catch (authorization_module.API.Exceptions.ResponseException ex)
        {
            _logger.LogWarning(ex, "Response exception during refresh token");
            
            if (ex.Message.Contains("Invalid") || ex.Message.Contains("expired"))
            {
                throw new RpcException(
                    new Status(StatusCode.Unauthenticated, ex.Message));
            }
            
            throw new RpcException(
                new Status(StatusCode.InvalidArgument, ex.Message));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during refresh token");
            throw new RpcException(
                new Status(StatusCode.Internal, "Internal server error occurred"));
        }
    }

    /// <summary>
    /// Подтверждение email
    /// </summary>
    public override async Task<MessageResponse> ConfirmEmail(
        GrpcConfirmEmailRequest request,
        ServerCallContext context)
    {
        try
        {
            _logger.LogInformation("ConfirmEmail gRPC request for userId: {UserId}", request.UserId);

            // Преобразуем gRPC запрос в DTO
            var confirmEmailDto = _mapper.Map<DtoConfirmEmailRequest>(request);

            // Подтверждение email
            var result = await _authService.ConfirmEmailAsync(confirmEmailDto);

            // Преобразуем DTO ответ в gRPC ответ
            var response = _mapper.Map<MessageResponse>(result);

            _logger.LogInformation("Email confirmed successfully for userId: {UserId}", request.UserId);

            return response;
        }
        catch (RpcException)
        {
            throw;
        }
        catch (authorization_module.API.Exceptions.ResponseException ex)
        {
            _logger.LogWarning(ex, "Response exception during confirm email: {UserId}", request.UserId);
            throw new RpcException(
                new Status(StatusCode.InvalidArgument, ex.Message));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during confirm email: {UserId}", request.UserId);
            throw new RpcException(
                new Status(StatusCode.Internal, "Internal server error occurred"));
        }
    }

    /// <summary>
    /// Повторная отправка письма подтверждения
    /// </summary>
    public override async Task<MessageResponse> ResendConfirmationEmail(
        GrpcResendConfirmationEmailRequest request,
        ServerCallContext context)
    {
        try
        {
            _logger.LogInformation("ResendConfirmationEmail gRPC request for email: {Email}", request.Email);

            var dto = _mapper.Map<DtoResendConfirmationEmailRequest>(request);
            var result = await _authService.ResendConfirmationEmailAsync(dto);
            var response = _mapper.Map<MessageResponse>(result);

            _logger.LogInformation("Confirmation email resent successfully for email: {Email}", request.Email);

            return response;
        }
        catch (RpcException)
        {
            throw;
        }
        catch (authorization_module.API.Exceptions.ResponseException ex)
        {
            _logger.LogWarning(ex, "Response exception during resend confirmation email: {Email}", request.Email);
            throw new RpcException(
                new Status(StatusCode.InvalidArgument, ex.Message));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during resend confirmation email: {Email}", request.Email);
            throw new RpcException(
                new Status(StatusCode.Internal, "Internal server error occurred"));
        }
    }

    /// <summary>
    /// Получение информации о текущем пользователе
    /// </summary>
    public override async Task<UserInfoResponse> GetUserInfo(
        GetUserInfoRequest request,
        ServerCallContext context)
    {
        try
        {
            // Получаем user_id из контекста (от агрегатора)
            var userId = GrpcContextHelper.GetUserId(context);
            
            // Проверяем, что user_id из запроса совпадает с user_id из контекста (если передан)
            if (!string.IsNullOrEmpty(request.UserId) && request.UserId != userId)
            {
                throw new RpcException(
                    new Status(StatusCode.PermissionDenied, "User ID mismatch"));
            }

            _logger.LogInformation("GetUserInfo gRPC request for userId: {UserId}", userId);

            // Получение информации о пользователе
            var result = await _authService.GetUserInfoAsync(userId);

            // Преобразуем DTO ответ в gRPC ответ
            var response = _mapper.Map<UserInfoResponse>(result);

            _logger.LogInformation("User info retrieved successfully for userId: {UserId}", userId);

            return response;
        }
        catch (RpcException)
        {
            throw;
        }
        catch (authorization_module.API.Exceptions.ResponseException ex)
        {
            _logger.LogWarning(ex, "Response exception during get user info");
            
            if (ex.Message.Contains("not found"))
            {
                throw new RpcException(
                    new Status(StatusCode.NotFound, ex.Message));
            }
            
            throw new RpcException(
                new Status(StatusCode.InvalidArgument, ex.Message));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during get user info");
            throw new RpcException(
                new Status(StatusCode.Internal, "Internal server error occurred"));
        }
    }

    public override async Task<UserInfoResponse> FindUserByEmail(
        FindUserByEmailRequest request,
        ServerCallContext context)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(request.Email))
            {
                throw new RpcException(new Status(StatusCode.InvalidArgument, "Email is required"));
            }

            var result = await _authService.FindUserByEmailAsync(request.Email);
            return _mapper.Map<UserInfoResponse>(result);
        }
        catch (RpcException)
        {
            throw;
        }
        catch (authorization_module.API.Exceptions.ResponseException ex)
        {
            _logger.LogWarning(ex, "Response exception during find user by email: {Email}", request.Email);
            throw new RpcException(new Status(StatusCode.NotFound, ex.Message));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during find user by email: {Email}", request.Email);
            throw new RpcException(new Status(StatusCode.Internal, "Internal server error occurred"));
        }
    }

    /// <summary>
    /// Выход пользователя
    /// </summary>
    public override async Task<MessageResponse> LogoutUser(
        LogoutUserRequest request,
        ServerCallContext context)
    {
        try
        {
            // Получаем user_id из контекста (от агрегатора)
            var userId = GrpcContextHelper.GetUserId(context);
            
            // Проверяем, что user_id из запроса совпадает с user_id из контекста (если передан)
            if (!string.IsNullOrEmpty(request.UserId) && request.UserId != userId)
            {
                throw new RpcException(
                    new Status(StatusCode.PermissionDenied, "User ID mismatch"));
            }

            _logger.LogInformation("LogoutUser gRPC request for userId: {UserId}", userId);

            // Выход пользователя
            var result = await _authService.LogoutUserAsync(userId, request.RefreshToken);

            // Преобразуем DTO ответ в gRPC ответ
            var response = _mapper.Map<MessageResponse>(result);

            _logger.LogInformation("User logged out successfully for userId: {UserId}", userId);

            return response;
        }
        catch (RpcException)
        {
            throw;
        }
        catch (authorization_module.API.Exceptions.ResponseException ex)
        {
            _logger.LogWarning(ex, "Response exception during logout: {UserId}", request.UserId);
            
            if (ex.Message.Contains("not found"))
            {
                throw new RpcException(
                    new Status(StatusCode.NotFound, ex.Message));
            }
            
            throw new RpcException(
                new Status(StatusCode.InvalidArgument, ex.Message));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during logout: {UserId}", request.UserId);
            throw new RpcException(
                new Status(StatusCode.Internal, "Internal server error occurred"));
        }
    }

    /// <summary>
    /// Обновление имени пользователя
    /// </summary>
    public override async Task<MessageResponse> UpdateUsername(
        GrpcUpdateUsernameRequest request,
        ServerCallContext context)
    {
        try
        {
            // Получаем user_id из контекста (от агрегатора)
            var userId = GrpcContextHelper.GetUserId(context);
            
            // Проверяем, что user_id из запроса совпадает с user_id из контекста (если передан)
            if (!string.IsNullOrEmpty(request.UserId) && request.UserId != userId)
            {
                throw new RpcException(
                    new Status(StatusCode.PermissionDenied, "User ID mismatch"));
            }

            _logger.LogInformation("UpdateUsername gRPC request for userId: {UserId}", userId);

            // Обновление имени пользователя
            var result = await _authService.UpdateUserNameAsync(userId, request.UserName);

            // Преобразуем DTO ответ в gRPC ответ
            var response = _mapper.Map<MessageResponse>(result);

            _logger.LogInformation("Username updated successfully for userId: {UserId}", userId);

            return response;
        }
        catch (RpcException)
        {
            throw;
        }
        catch (authorization_module.API.Exceptions.ResponseException ex)
        {
            _logger.LogWarning(ex, "Response exception during update username: {UserId}", request.UserId);
            
            if (ex.Message.Contains("not found"))
            {
                throw new RpcException(
                    new Status(StatusCode.NotFound, ex.Message));
            }
            
            if (ex.Message.Contains("already taken") || ex.Message.Contains("cannot be empty"))
            {
                throw new RpcException(
                    new Status(StatusCode.InvalidArgument, ex.Message));
            }
            
            throw new RpcException(
                new Status(StatusCode.InvalidArgument, ex.Message));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during update username: {UserId}", request.UserId);
            throw new RpcException(
                new Status(StatusCode.Internal, "Internal server error occurred"));
        }
    }

    /// <summary>
    /// Обновление пароля пользователя
    /// </summary>
    public override async Task<MessageResponse> UpdatePassword(
        GrpcUpdatePasswordRequest request,
        ServerCallContext context)
    {
        try
        {
            // Получаем user_id из контекста (от агрегатора)
            var userId = GrpcContextHelper.GetUserId(context);
            
            // Проверяем, что user_id из запроса совпадает с user_id из контекста (если передан)
            if (!string.IsNullOrEmpty(request.UserId) && request.UserId != userId)
            {
                throw new RpcException(
                    new Status(StatusCode.PermissionDenied, "User ID mismatch"));
            }

            _logger.LogInformation("UpdatePassword gRPC request for userId: {UserId}", userId);

            // Обновление пароля пользователя
            var result = await _authService.UpdateUserPasswordAsync(userId, request.CurrentPassword, request.NewPassword);

            // Преобразуем DTO ответ в gRPC ответ
            var response = _mapper.Map<MessageResponse>(result);

            _logger.LogInformation("Password updated successfully for userId: {UserId}", userId);

            return response;
        }
        catch (RpcException)
        {
            throw;
        }
        catch (authorization_module.API.Exceptions.ResponseException ex)
        {
            _logger.LogWarning(ex, "Response exception during update password: {UserId}", request.UserId);
            
            if (ex.Message.Contains("not found"))
            {
                throw new RpcException(
                    new Status(StatusCode.NotFound, ex.Message));
            }
            
            if (ex.Message.Contains("cannot be empty") || ex.Message.Contains("incorrect"))
            {
                throw new RpcException(
                    new Status(StatusCode.InvalidArgument, ex.Message));
            }
            
            throw new RpcException(
                new Status(StatusCode.InvalidArgument, ex.Message));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during update password: {UserId}", request.UserId);
            throw new RpcException(
                new Status(StatusCode.Internal, "Internal server error occurred"));
        }
    }

    /// <summary>
    /// Обновление URL аватара профиля
    /// </summary>
    public override async Task<MessageResponse> UpdateAvatarUrl(
        GrpcUpdateAvatarUrlRequest request,
        ServerCallContext context)
    {
        try
        {
            var userId = GrpcContextHelper.GetUserId(context);

            if (!string.IsNullOrEmpty(request.UserId) && request.UserId != userId)
            {
                throw new RpcException(
                    new Status(StatusCode.PermissionDenied, "User ID mismatch"));
            }

            _logger.LogInformation("UpdateAvatarUrl gRPC request for userId: {UserId}", userId);

            var result = await _authService.UpdateAvatarUrlAsync(userId, request.AvatarUrl);

            var response = _mapper.Map<MessageResponse>(result);

            _logger.LogInformation("Avatar URL updated successfully for userId: {UserId}", userId);

            return response;
        }
        catch (RpcException)
        {
            throw;
        }
        catch (authorization_module.API.Exceptions.ResponseException ex)
        {
            _logger.LogWarning(ex, "Response exception during update avatar url: {UserId}", request.UserId);

            if (ex.Message.Contains("not found"))
            {
                throw new RpcException(
                    new Status(StatusCode.NotFound, ex.Message));
            }

            throw new RpcException(
                new Status(StatusCode.InvalidArgument, ex.Message));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during update avatar url: {UserId}", request.UserId);
            throw new RpcException(
                new Status(StatusCode.Internal, "Internal server error occurred"));
        }
    }

    /// <summary>
    /// Получение списка всех пользователей (только для Admin)
    /// </summary>
    public override async Task<GetUsersListResponse> GetUsersList(
        GetUsersListRequest request,
        ServerCallContext context)
    {
        try
        {
            _logger.LogInformation("GetUsersList gRPC request");

            var page = request.Page > 0 ? request.Page : 1;
            var pageSize = request.PageSize > 0 ? request.PageSize : 50;
            var search = string.IsNullOrWhiteSpace(request.Search) ? null : request.Search;

            var (users, totalCount) = await _authService.GetUsersListAsync(page, pageSize, search);

            var response = new GetUsersListResponse
            {
                TotalCount = totalCount
            };

            response.Users.AddRange(users.Select(u => new UserListDto
            {
                Id = u.Id,
                UserName = u.UserName,
                Email = u.Email,
                RegistrationDate = "", // Not tracked in Identity by default
                IsLockedOut = false    // Will be enriched below
            }));

            return response;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during GetUsersList");
            throw new RpcException(
                new Status(StatusCode.Internal, "Internal server error occurred"));
        }
    }

    /// <summary>
    /// Бан/разбан пользователя (только для Admin)
    /// </summary>
    public override async Task<MessageResponse> AdminSetUserLockout(
        AdminSetUserLockoutRequest request,
        ServerCallContext context)
    {
        try
        {
            _logger.LogInformation("AdminSetUserLockout gRPC request for user {UserId}, lock={Lock}", request.UserId, request.Lock);

            var result = await _authService.AdminSetUserLockoutAsync(request.UserId, request.Lock);

            return new MessageResponse { Message = result.Data };
        }
        catch (authorization_module.API.Exceptions.ResponseException ex)
        {
            _logger.LogWarning(ex, "AdminSetUserLockout failed for user {UserId}", request.UserId);
            throw new RpcException(
                new Status(StatusCode.NotFound, ex.Message));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during AdminSetUserLockout");
            throw new RpcException(
                new Status(StatusCode.Internal, "Internal server error occurred"));
        }
    }
}
