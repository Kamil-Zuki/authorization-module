using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using authorization_module.API.Interfaces;

namespace authorization_module.API.Services;

public class EmailService(IConfiguration configuration, ILogger<EmailService> logger) : IEmailService
{
    // Email:Password holds the Resend API key (re_...)
    private readonly string _resendApiKey = configuration["Email:Password"]!;
    private readonly string _senderEmail = configuration["Email:Address"]!;
    private readonly string _displayName = configuration["Email:DisplayName"]!;
    private readonly ILogger<EmailService> _logger = logger;

    public async Task<bool> SendEmailAsync(string toEmail, string subject, string body)
    {
        try
        {
            using var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", _resendApiKey);

            var payload = new
            {
                from = $"{_displayName} <{_senderEmail}>",
                to = new[] { toEmail },
                subject,
                html = body
            };

            var json = JsonSerializer.Serialize(payload);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await httpClient.PostAsync("https://api.resend.com/emails", content);

            if (response.IsSuccessStatusCode)
            {
                _logger.LogInformation("Email sent via Resend API to {ToEmail}", toEmail);
                return true;
            }

            var errorBody = await response.Content.ReadAsStringAsync();
            _logger.LogError("Resend API error {StatusCode}: {Body}", (int)response.StatusCode, errorBody);
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error sending email to {ToEmail}", toEmail);
            return false;
        }
    }
}

