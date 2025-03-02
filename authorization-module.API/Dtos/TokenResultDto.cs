namespace authorization_module.API.Dtos
{
    public class TokenResultDto
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
    }
}
