namespace Glosslore_authorization.Web.Models.Identity;

public class ScopeAttribute : Attribute
{
    public string Scope { get; set; }

    public ScopeAttribute(string scope)
    {
        Scope = scope;
    }
}