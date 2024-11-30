namespace authorization_module.API.Dtos
{
    public record AuthResultDto(
        bool Succeeded,
        object? Data = null,
        List<string>? Errors = null
    );
}
