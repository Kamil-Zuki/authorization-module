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
builder.WebHost.UseUrls("http://*:80"); // Consider using HTTPS in production
#endif

// 🔹 Add services
builder.Services.AddControllers();

// 🔹 Database Configuration
builder.Services.AddDbContext<DataContext>(opt =>
    opt.UseNpgsql(builder.Configuration.GetConnectionString("Db")));

// 🔹 Identity Configuration
builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<DataContext>()
    .AddDefaultTokenProviders();

// 🔹 CORS Configuration
builder.Services.AddCors(options => options.AddPolicy("cors", policy =>
{
    policy.AllowAnyHeader()
          .AllowAnyMethod()
          .AllowAnyOrigin();
}));

// 🔹 Prevent Redirection to `/Account/Login` (Fix 404 Issue)
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Events.OnRedirectToLogin = context =>
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        return Task.CompletedTask;
    };
});

// 🔹 IdentityServer Configuration
builder.Services.AddIdentityServer()
    .AddAspNetIdentity<ApplicationUser>()
    .AddConfigurationStore(options =>
    {
        options.ConfigureDbContext = b => b.UseNpgsql(builder.Configuration.GetConnectionString("Db"));
    })
    .AddOperationalStore(options =>
    {
        options.ConfigureDbContext = b => b.UseNpgsql(builder.Configuration.GetConnectionString("Db"));
        options.EnableTokenCleanup = true; // Cleanup expired tokens
        options.TokenCleanupInterval = 3600; // Run cleanup every hour
    })
    .AddInMemoryClients(new[] // Define OAuth Clients
    {
        new Client
        {
            ClientId = "auth-microservice",
            ClientSecrets = { new Secret(builder.Configuration["IdentityServer:ClientSecret"]?.Sha256() ?? "default_secret".Sha256()) },
            AllowedGrantTypes = GrantTypes.ResourceOwnerPassword, // Password authentication
            AllowedScopes = { "api1", "offline_access" }, // API Access & Refresh tokens
            AllowOfflineAccess = true, // Enable Refresh tokens
            RefreshTokenUsage = TokenUsage.OneTimeOnly,
            RefreshTokenExpiration = TokenExpiration.Sliding,
            SlidingRefreshTokenLifetime = 604800 // 7 days (1 week)
        }
    })
    .AddInMemoryApiScopes(new[]
    {
        new ApiScope("api1", "API Access"),
        new ApiScope("offline_access", "Offline Access")
    })
    .AddDeveloperSigningCredential(); // Replace with a production certificate

// 🔹 JWT Authentication Configuration
var jwtSecret = builder.Configuration["Jwt:Secret"];
if (string.IsNullOrEmpty(jwtSecret))
{
    throw new InvalidOperationException("JWT Secret is missing in configuration.");
}

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.Authority = builder.Configuration["IdentityServer:Authority"];
    options.Audience = builder.Configuration["Jwt:Audience"];
    options.RequireHttpsMetadata = false;

    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret))
    };
});

// 🔹 Authorization
builder.Services.AddAuthorization();

// 🔹 Additional Services
builder.Services.AddHttpClient();
builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IEmailService, EmailService>();
builder.Services.AddScoped<IValidator<UserRegistrationRequest>, UserRegistrationValidator>();
builder.Services.AddScoped<IValidator<UserLoginRequest>, UserLoginValidator>();

// 🔹 Swagger Configuration
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
                TokenUrl = new Uri(builder.Configuration["IdentityServer:TokenEndpoint"] ?? "http://localhost:5027/connect/token"),
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

var app = builder.Build();

// 🔹 Middleware Pipeline
app.UseCors("cors");
app.UseAuthentication();
app.UseAuthorization();
// app.UseHttpsRedirection(); // Uncomment if using HTTPS
app.UseIdentityServer();

// 🔹 Swagger Middleware
app.UseSwagger(c =>
{
    c.RouteTemplate = "authorization-module/swagger/{documentname}/swagger.json";
});
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/authorization-module/swagger/v1/swagger.json", "Authorization API");
    c.RoutePrefix = "authorization-module/swagger";
    c.OAuthClientId("auth-microservice");
    c.OAuthClientSecret(builder.Configuration["IdentityServer:ClientSecret"]);
    c.OAuthUsePkce();
});

// 🔹 Map Controllers
app.MapControllers();

// 🔹 Exception Handling Middleware (Optional)
// app.UseMiddleware<ExceptionHandlingMiddleware>();

app.Use(async (context, next) =>
{
    Console.WriteLine($"Request: {context.Request.Method} {context.Request.Path}");
    await next.Invoke();
});



app.Run();
