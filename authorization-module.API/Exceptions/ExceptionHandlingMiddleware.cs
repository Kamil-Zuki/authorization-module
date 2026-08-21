using authorization_module.API.Dtos;

namespace authorization_module.API.Exceptions
{
    public class ExceptionHandlingMiddleware(RequestDelegate next, ILogger<ExceptionHandlingMiddleware> logger)
    {
        private readonly RequestDelegate _next = next;
        private readonly ILogger<ExceptionHandlingMiddleware> _logger = logger;

        public async Task Invoke(HttpContext context)
        {
            try
            {
                await _next(context);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unhandled exception occurred.");
                await HandleExceptionAsync(context, ex, _logger);
            }
        }

        public static Task HandleExceptionAsync(HttpContext context, Exception exception, ILogger logger)
        {
            context.Response.ContentType = "application/json";

            var statusCode = exception switch
            {
                ResponseException => StatusCodes.Status400BadRequest,
                UnauthorizedAccessException => StatusCodes.Status401Unauthorized,
                _ => StatusCodes.Status500InternalServerError
            };

            context.Response.StatusCode = statusCode;

            var errorMessages = new List<ErrorResponseMessage>();

            if (exception is ResponseException responseException)
            {
                errorMessages.AddRange(responseException.Errors);
            }
            else
            {
                errorMessages.Add(new ErrorResponseMessage
                {
                    StatusCode = statusCode,
                    ErrorMessage = exception.Message
                });
            }

            var errorResponse = new
            {
                Errors = errorMessages,
#if DEBUG
                //Details = exception.StackTrace
#endif
            };

            logger.LogError(exception, "An error occurred: {Message}", exception.Message);

            return context.Response.WriteAsJsonAsync(errorResponse);
        }
    }
}
