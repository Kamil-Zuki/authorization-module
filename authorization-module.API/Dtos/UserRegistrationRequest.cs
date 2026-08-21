namespace authorization_module.API.Dtos;

public class UserRegistrationRequest
{
    public required string Email { get; set; }
    public required string Password { get; set; }
    public required string ConfirmPassword { get; set; }
}

