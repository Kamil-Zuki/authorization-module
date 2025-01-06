namespace authorization_module.API.Interfaces
{
    public interface ITokenService
    {
        string GenerateJwtToken(string userId, string userName);
    }
}
