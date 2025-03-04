using authorization_module.API.Data;
using authorization_module.API.Data.Entities;
using authorization_module.API.Dtos;
using authorization_module.API.Interfaces;
using authorization_module.API.Services;
using authorization_module.API.Validations;
using Duende.IdentityServer.Models;
using FluentValidation;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.Filters;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

#if RELEASE
builder.WebHost.UseUrls("http://*:80"); // Consider HTTPS in production
#endif

// Add services
builder.Services.AddControllers();

// Database
builder.Services.AddDbContext<DataContext>(opt =>
    opt.UseNpgsql(builder.Configuration.GetConnectionString("Db")));

// Identity
builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<DataContext>()
    .AddDefaultTokenProviders();

// CORS
builder.Services.AddCors(options => options.AddPolicy("cors", policy =>
{
    policy.AllowAnyHeader()
          .AllowAnyMethod()
          .AllowAnyOrigin();
}));

// IdentityServer
builder.Services.AddIdentityServer()
    .AddAspNetIdentity<ApplicationUser>() // Integrate with Identity users
    .AddConfigurationStore(options =>
    {
        options.ConfigureDbContext = b => b.UseNpgsql(builder.Configuration.GetConnectionString("Db"));
    })
    .AddOperationalStore(options =>
    {
        options.ConfigureDbContext = b => b.UseNpgsql(builder.Configuration.GetConnectionString("Db"));
        options.EnableTokenCleanup = true; // Clean expired tokens
        options.TokenCleanupInterval = 3600; // Hourly cleanup
    })
    .AddInMemoryClients(new[]
    {
        new Client
        {
            ClientId = "auth-microservice",
            ClientSecrets = { new Secret("your-secret".Sha256()) },
            AllowedGrantTypes = GrantTypes.ResourceOwnerPassword, // For username/password login
            AllowedScopes = { "api1", "offline_access" }, // API access + refresh tokens
            AllowOfflineAccess = true, // Enable refresh tokens
            RefreshTokenUsage = TokenUsage.OneTimeOnly, // New refresh token each time
            RefreshTokenExpiration = TokenExpiration.Sliding,
            SlidingRefreshTokenLifetime = 604800 // 7 days
        }
    })
    .AddInMemoryApiScopes(new[]
    {
        new ApiScope("api1", "API Access"),
        new ApiScope("offline_access", "Offline Access")
    })
    .AddDeveloperSigningCredential(); // Use a real cert in production

// Swagger
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo { Title = "Auth API", Version = "v1" });
    options.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
    {
        Type = SecuritySchemeType.OAuth2,
        Flows = new OpenApiOAuthFlows
        {
            Password = new OpenApiOAuthFlow
            {
                TokenUrl = new Uri(builder.Configuration["IdentityServer:TokenEndpoint"]),
                Scopes = new Dictionary<string, string>
                {
                    { "api1", "API Access" },
                    { "offline_access", "Offline Access" }
                }
            }
        }
    });
    options.OperationFilter<SecurityRequirementsOperationFilter>();
});

// Authentication
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = builder.Configuration["IdentityServer:Authority"];
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = false // Adjust based on your needs
        };
    });

// Authorization
builder.Services.AddAuthorization();

// Additional services
builder.Services.AddHttpClient(); // For AuthService token endpoint calls
builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IEmailService, EmailService>();
builder.Services.AddScoped<IValidator<UserRegistrationRequest>, UserRegistrationValidator>();
builder.Services.AddScoped<IValidator<UserLoginRequest>, UserLoginValidator>();

var app = builder.Build();

// Middleware pipeline
app.UseCors("cors");
app.UseAuthentication();
app.UseAuthorization();
app.UseHttpsRedirection(); // Remove if using HTTP only in RELEASE
app.UseIdentityServer();
app.UseSwagger(c =>
{
    c.RouteTemplate = "authorization-module/swagger/{documentname}/swagger.json";
});
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/authorization-module/swagger/v1/swagger.json", "Authorization API");
    c.RoutePrefix = "authorization-module/swagger";
    c.OAuthClientId("auth-microservice");
    c.OAuthClientSecret("your-secret");
    c.OAuthUsePkce();
});
app.MapControllers();
// app.UseMiddleware<ExceptionHandlingMiddleware>(); // Uncomment if defined

app.Run();