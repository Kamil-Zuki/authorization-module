namespace authorization_module.API.Dtos;

public class ErrorResponseMessage
{
    public required int Code { get; set; }
    public required string Message { get; set; }
}

