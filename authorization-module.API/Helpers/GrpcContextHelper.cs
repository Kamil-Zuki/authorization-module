using Grpc.Core;
using System.Security.Claims;

namespace authorization_module.API.Helpers;

/// <summary>
/// Вспомогательный класс для работы с ServerCallContext
/// </summary>
public static class GrpcContextHelper
{
    /// <summary>
    /// Извлекает user_id из ServerCallContext
    /// </summary>
    /// <param name="context">Контекст gRPC вызова</param>
    /// <returns>Идентификатор пользователя</returns>
    /// <exception cref="RpcException">Если user_id не найден</exception>
    public static string GetUserId(ServerCallContext context)
    {
        // Пытаемся получить из метаданных (заголовков)
        var userIdHeader = context.RequestHeaders.FirstOrDefault(h => h.Key == "user_id");
        if (userIdHeader != null && !string.IsNullOrEmpty(userIdHeader.Value))
        {
            return userIdHeader.Value;
        }

        // Пытаемся получить из Claims (если используется аутентификация)
        var userIdClaim = context.GetHttpContext()?.User?.FindFirst("user_id")?.Value
            ?? context.GetHttpContext()?.User?.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        if (userIdClaim != null && !string.IsNullOrEmpty(userIdClaim))
        {
            return userIdClaim;
        }

        throw new RpcException(
            new Status(StatusCode.Unauthenticated, "User ID not found in request context"));
    }

    /// <summary>
    /// Извлекает роли из ServerCallContext
    /// </summary>
    /// <param name="context">Контекст gRPC вызова</param>
    /// <returns>Список ролей</returns>
    public static List<string> GetRoles(ServerCallContext context)
    {
        var roles = new List<string>();

        // Пытаемся получить из метаданных
        var rolesHeader = context.RequestHeaders.FirstOrDefault(h => h.Key == "roles");
        if (rolesHeader != null)
        {
            roles.AddRange(rolesHeader.Value.Split(',', StringSplitOptions.RemoveEmptyEntries));
        }

        // Пытаемся получить из Claims
        var roleClaims = context.GetHttpContext()?.User?.FindAll(ClaimTypes.Role);
        if (roleClaims != null)
        {
            roles.AddRange(roleClaims.Select(c => c.Value));
        }

        return roles.Distinct().ToList();
    }

    /// <summary>
    /// Проверяет, имеет ли пользователь указанную роль
    /// </summary>
    /// <param name="context">Контекст gRPC вызова</param>
    /// <param name="role">Роль для проверки</param>
    /// <returns>True, если пользователь имеет роль</returns>
    public static bool HasRole(ServerCallContext context, string role)
    {
        return GetRoles(context).Contains(role, StringComparer.OrdinalIgnoreCase);
    }
}

