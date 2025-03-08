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

// 🔹 IdentityServer Configuration (🔴 Make sure you have configured IdentityServer!)
builder.Services.AddIdentityServer()
    .AddAspNetIdentity<ApplicationUser>()
    .AddDeveloperSigningCredential() // Replace with real signing credentials in production
    .AddInMemoryClients(new List<Client>
    {
        new Client
        {
            ClientId = builder.Configuration["IdentityServer:ClientId"], // "auth-microservice"
            ClientSecrets = { new Secret(builder.Configuration["IdentityServer:ClientSecret"].Sha256()) }, // "your-secret"
            AllowedGrantTypes = GrantTypes.ResourceOwnerPasswordAndClientCredentials, // Allow password and client credentials
            AllowedScopes = {
                builder.Configuration["IdentityServer:Scope"],  // "api1 offline_access"
                "api1",
                "offline_access"
            },
            AccessTokenLifetime = 3600, // Token lifetime in seconds (optional)
            AllowOfflineAccess = true // Enable offline access for refresh tokens
        }
    })
    .AddInMemoryApiScopes(new List<ApiScope>
    {
        new ApiScope("api1", "Your API") // Replace with your actual API scope
    })
    .AddInMemoryIdentityResources(new List<IdentityResource>
    {
        new IdentityResources.OpenId(),
        new IdentityResources.Profile()
    });

// 🔹 CORS Configuration
builder.Services.AddCors(options => options.AddPolicy("cors", policy =>
{
    policy.AllowAnyHeader()
          .AllowAnyMethod()
          .AllowAnyOrigin();
}));

// 🔹 Prevent Redirection to `/Account/Login` (Fix 404 Issue)
//builder.Services.ConfigureApplicationCookie(options =>
//{
//    options.Events.OnRedirectToLogin = context =>
//    {
//        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
//        return Task.CompletedTask;
//    };
//});

// 🔹 JWT Authentication Configuration (HS256)
var jwtSettings = builder.Configuration.GetSection("Jwt");
var key = Encoding.UTF8.GetBytes(jwtSettings["Secret"] ?? "default_secret_key");

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["IdentityServer:Authority"], // "http://localhost:5027"
            ValidAudience = builder.Configuration["IdentityServer:Scope"], // "api1 offline_access"
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ClockSkew = TimeSpan.Zero
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
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Enter 'Bearer <token>'"
    });
    options.OperationFilter<SecurityRequirementsOperationFilter>();
});

var app = builder.Build();

// 🔹 Middleware Pipeline (Correct Order!)
app.UseCors("cors");
app.UseIdentityServer(); // ⬅️ Must be before authentication!
app.UseAuthentication();
app.UseAuthorization();

// 🔹 Swagger Middleware
app.UseSwagger(c =>
{
    c.RouteTemplate = "authorization-module/swagger/{documentname}/swagger.json";
});
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/authorization-module/swagger/v1/swagger.json", "Authorization API");
    c.RoutePrefix = "authorization-module/swagger";
});

// 🔹 Map Controllers
app.MapControllers();

// 🔹 Logging Middleware
app.Use(async (context, next) =>
{
    Console.WriteLine($"Request: {context.Request.Method} {context.Request.Path}");
    await next.Invoke();
});

app.Run();
