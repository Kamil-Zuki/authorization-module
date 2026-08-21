namespace authorization_module.API.Dtos
{
    public class UpdatePasswordRequest
    {
        public string CurrentPassword {get; set;}
        public string NewPassword { get; set;}
    }
}
