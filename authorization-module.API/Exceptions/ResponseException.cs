namespace authorization_module.API.Dtos;

public class ResponseException : Exception
{
    public List<ErrorResponseMessage> Errors { get; }

    public ResponseException(List<ErrorResponseMessage> errors)
        : base("An errors occurred.")
    {
        Errors = errors ?? throw new ArgumentNullException(nameof(errors), "Errors cannot be null.");
    }
}

