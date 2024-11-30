using authorization_module.API.Interfaces;
using FluentEmail.Core;
using FluentEmail.Smtp;
using System.Net;
using System.Net.Mail;
namespace authorization_module.API.Services;
public class EmailService(IConfiguration configuration, ILogger<EmailService> logger) : IEmailService
{
    private readonly string _smtpHost = configuration["Email:Host"]!;
    private readonly int _smtpPort = int.Parse(configuration["Email:Port"]!);
    private readonly string _smtpUserName = configuration["Email:UserName"]!;
    private readonly string _smtpPassword = configuration["Email:Password"]!;
    private readonly string _senderEmail = configuration["Email:Address"]!;
    private readonly string _displayName = configuration["Email:DisplayName"]!;
    private readonly ILogger<EmailService> _logger = logger;

    public async Task<bool> SendEmailAsync(string toEmail, string subject, string body)
    {
        try
        {
            var email = Email
                .From(_senderEmail, _displayName)
                .To(toEmail)
                .Subject(subject)
                .Body(body);

            var smtp = new SmtpSender(() => new SmtpClient(_smtpHost)
            {
                UseDefaultCredentials = false,
                Credentials = new NetworkCredential(_smtpUserName, _smtpPassword),
                Port = _smtpPort,
                EnableSsl = true
            });

            Email.DefaultSender = smtp;
            var result = await email.SendAsync();

            return result.Successful;
        }
        catch (Exception ex)
        {
            _logger.LogError($"Error sending email: {ex.Message}");
            return false;
        }
    }
}
