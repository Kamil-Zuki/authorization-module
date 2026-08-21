namespace authorization_module.API.Dtos;

public class ErrorResponseMessage
{
    public required int StatusCode { get; set; }
    public required string ErrorMessage { get; set; }
}

