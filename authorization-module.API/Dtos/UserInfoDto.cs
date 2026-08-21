namespace authorization_module.API.Dtos
{
    public class UserInfoDto
    {
        public string Id { get; set; } = string.Empty;
        public string UserName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public bool EmailConfirmed { get; set; }

        /// <summary>Public HTTPS URL of the profile picture (stored in media or external).</summary>
        public string? AvatarUrl { get; set; }
    }
}
