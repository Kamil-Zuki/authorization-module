using authorization_module.API.Dtos;

public class ResponseException : Exception
{
    public List<ErrorResponseMessage> Errors { get; }

    public ResponseException(IEnumerable<ErrorResponseMessage> errors)
    {
        Errors = errors.ToList();
    }

    public ResponseException(string message)
    {
        Errors = new List<ErrorResponseMessage>
        {
            new()
            {
                StatusCode = StatusCodes.Status400BadRequest,
                ErrorMessage = message
            }
        };
    }
}
