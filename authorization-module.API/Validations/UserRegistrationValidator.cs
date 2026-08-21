using authorization_module.API.Dtos;
using FluentValidation;

namespace authorization_module.API.Validations
{
    public class UserRegistrationValidator : AbstractValidator<UserRegistrationRequest>
    {
        public UserRegistrationValidator()
        {
            RuleFor(x => x.Email).NotEmpty().EmailAddress();
            RuleFor(x => x.Password).NotEmpty().MinimumLength(6).Matches(@"^(?=.*[A-Z])(?=.*[\W_]).+$")
                .WithMessage("Password must contain at least one uppercase letter and one special character.");
            RuleFor(x => x.ConfirmPassword).Equal(x => x.Password).WithMessage("Passwords must match.");
        }
    }
}
