namespace authorization_module.API.Dtos
{
    public class UpdateProfileRequest
    {
        public required string Username { get; set; }
        public required string Email { get; set; }
    }
}
