namespace authorization_module.API.Dtos
{
    public class RefreshTokenDto
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
    }
}
