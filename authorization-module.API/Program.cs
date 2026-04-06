using authorization_module.API.Data;
using authorization_module.API.Data.Entities;
using authorization_module.API.Dtos;
using authorization_module.API.Exceptions;
using authorization_module.API.Interfaces;
using authorization_module.API.Mappers;
using authorization_module.API.Services;
using authorization_module.API.Validations;
using FluentValidation;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.Filters;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

var corsOrigins = GetCorsOrigins(builder.Configuration);
ValidateAuthorizationConfiguration(builder.Configuration, builder.Environment, corsOrigins);

// В режиме RELEASE используем UseUrls
// В режиме разработки используем ListenLocalhost из ConfigureKestrel
#if RELEASE
builder.WebHost.UseUrls("http://*:80");
#endif

builder.Services.AddControllers();

builder.Services.AddDbContext<DataContext>(opt =>
    opt.UseNpgsql(builder.Configuration.GetConnectionString("Db")));


builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
        .AddEntityFrameworkStores<DataContext>()
        .AddDefaultTokenProviders();

builder.Services.AddCors(options => options.AddPolicy("cors", policy =>
{
    policy.WithOrigins(corsOrigins)
          .AllowAnyHeader()
          .AllowAnyMethod()
          .AllowCredentials();
}));



builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IEmailService, EmailService>();


builder.Services.AddAutoMapper(cfg => { }, typeof(AutoMappingProfile));
//validation
builder.Services.AddScoped<IValidator<UserRegistrationRequest>, UserRegistrationValidator>();
builder.Services.AddScoped<IValidator<UserLoginRequest>, UserLoginValidator>();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo { Title = "Personal Vocabulary API", Version = "v1" });
    options.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey
    });
    options.OperationFilter<SecurityRequirementsOperationFilter>();
});

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration.GetValue<string>("Jwt:Issuer"),
        ValidAudience = builder.Configuration.GetValue<string>("Jwt:Audience"),
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration.GetValue<string>("Jwt:Secret")!))
    };
});


builder.Services.AddAuthorization();

// Настройка Kestrel для поддержки HTTP/2 без TLS (для локальной разработки)
// Без явного Protocols = Http2 gRPC-клиент получает HttpRequestException (RequestVersionExact HTTP/2).
// В контейнере слушаем на всех интерфейсах (0.0.0.0), иначе только loopback.
builder.WebHost.ConfigureKestrel(options =>
{
    var inContainer = string.Equals(Environment.GetEnvironmentVariable("DOTNET_RUNNING_IN_CONTAINER"), "true", StringComparison.OrdinalIgnoreCase);
    var listenAddress = inContainer ? System.Net.IPAddress.Any : System.Net.IPAddress.Loopback;
    options.Listen(listenAddress, 5027, listenOptions => listenOptions.Protocols = HttpProtocols.Http1AndHttp2);
});

builder.Services.AddGrpc(options =>
{
    options.MaxSendMessageSize = 1000 * 1024 * 1024; // 1 GB
    options.MaxReceiveMessageSize = 1000 * 1024 * 1024; // 1 GB
    options.EnableDetailedErrors = builder.Environment.IsDevelopment();
});

var app = builder.Build();

app.UseMiddleware<ExceptionHandlingMiddleware>();

app.UseCors("cors");

app.UseAuthentication();

app.UseAuthorization();

//app.UseHttpsRedirection();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger(c =>
    {
        c.RouteTemplate = "authorization-module/swagger/{documentname}/swagger.json";
    });
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/authorization-module/swagger/v1/swagger.json", "Authorization API");
        c.RoutePrefix = "authorization-module/swagger";
    });
}

// Map gRPC services
app.MapGrpcService<authorization_module.API.Api.Grpc.AuthService>();
app.MapGet("/healthz", () => Results.Ok(new { status = "ok" }));

app.MapControllers();

app.Run();

string[] GetCorsOrigins(IConfiguration configuration)
{
    var configuredOrigins = configuration["Cors:AllowedOrigins"];
    if (!string.IsNullOrWhiteSpace(configuredOrigins))
    {
        return SplitOrigins(configuredOrigins);
    }

    var legacyOrigins = configuration.GetSection("Cors:Urls").Get<string[]>();
    if (legacyOrigins is { Length: > 0 })
    {
        return legacyOrigins
            .Select(origin => origin.Trim())
            .Where(origin => !string.IsNullOrWhiteSpace(origin))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    return ["http://localhost:3000", "http://localhost:5000"];
}

void ValidateAuthorizationConfiguration(
    IConfiguration configuration,
    IWebHostEnvironment environment,
    string[] allowedOrigins)
{
    if (environment.IsDevelopment())
    {
        return;
    }

    var errors = new List<string>();

    ValidateJwtConfiguration(configuration, errors);
    ValidateConfirmationLink(configuration, errors);
    ValidateEmailConfiguration(configuration, errors);
    ValidateCorsConfiguration(allowedOrigins, errors);

    if (errors.Count > 0)
    {
        throw new InvalidOperationException(
            "authorization-module is missing required production configuration:" +
            $"{Environment.NewLine}- {string.Join($"{Environment.NewLine}- ", errors)}");
    }
}

void ValidateJwtConfiguration(IConfiguration configuration, List<string> errors)
{
    var jwtSecret = configuration["Jwt:Secret"];
    if (string.IsNullOrWhiteSpace(jwtSecret) ||
        jwtSecret.Length < 32 ||
        LooksLikePlaceholder(jwtSecret))
    {
        errors.Add("Jwt:Secret must be set to a non-placeholder value with at least 32 characters.");
    }

    if (string.IsNullOrWhiteSpace(configuration["Jwt:Issuer"]) || LooksLikePlaceholder(configuration["Jwt:Issuer"]!))
    {
        errors.Add("Jwt:Issuer must be configured.");
    }

    if (string.IsNullOrWhiteSpace(configuration["Jwt:Audience"]) || LooksLikePlaceholder(configuration["Jwt:Audience"]!))
    {
        errors.Add("Jwt:Audience must be configured.");
    }
}

void ValidateConfirmationLink(IConfiguration configuration, List<string> errors)
{
    var confirmationLink = configuration["ConfirmationLink"];
    if (string.IsNullOrWhiteSpace(confirmationLink) ||
        !Uri.TryCreate(confirmationLink, UriKind.Absolute, out var parsedUri) ||
        (parsedUri.Scheme != Uri.UriSchemeHttp && parsedUri.Scheme != Uri.UriSchemeHttps) ||
        LooksLikePlaceholder(confirmationLink))
    {
        errors.Add("ConfirmationLink must be an absolute public URL that points to the email confirmation endpoint.");
    }
}

void ValidateEmailConfiguration(IConfiguration configuration, List<string> errors)
{
    var requiredEmailKeys = new[]
    {
        "Email:Host",
        "Email:UserName",
        "Email:Password",
        "Email:Address",
        "Email:DisplayName"
    };

    foreach (var key in requiredEmailKeys)
    {
        var value = configuration[key];
        if (string.IsNullOrWhiteSpace(value) || LooksLikePlaceholder(value))
        {
            errors.Add($"{key} must be configured with a real value.");
        }
    }

    if (!int.TryParse(configuration["Email:Port"], out var port) || port <= 0)
    {
        errors.Add("Email:Port must be a positive integer.");
    }
}

void ValidateCorsConfiguration(string[] allowedOrigins, List<string> errors)
{
    if (allowedOrigins.Length == 0)
    {
        errors.Add("Cors:AllowedOrigins must contain at least one origin.");
        return;
    }

    if (allowedOrigins.Any(origin => origin == "*"))
    {
        errors.Add("Cors:AllowedOrigins cannot contain '*'.");
    }
}

string[] SplitOrigins(string configuredOrigins) =>
    configuredOrigins
        .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToArray();

bool LooksLikePlaceholder(string value) =>
    value.Contains("change-me", StringComparison.OrdinalIgnoreCase) ||
    value.Contains("example", StringComparison.OrdinalIgnoreCase) ||
    value.Contains("yourdomain", StringComparison.OrdinalIgnoreCase) ||
    value.Contains("yoursecretkeyhere", StringComparison.OrdinalIgnoreCase);
