namespace authorization_module.API.Dtos;

public class ConfirmEmailRequest
{
    public required string UserId { get; set; }
    public required string Token { get; set; }
}

