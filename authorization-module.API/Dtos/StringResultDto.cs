namespace authorization_module.API.Dtos;

public class StringResultDto(string message)
{
    public string Data { get; } = message;
}

