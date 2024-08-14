using ehs_API.Data;
using Google;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using System.Text;
using Microsoft.EntityFrameworkCore;
using ehs_API.Service;
using ehs_API.Middlewares;

var builder = WebApplication.CreateBuilder(args);

// Configure AutoMapper
builder.Services.AddAutoMapper(typeof(Program));

// Configure Entity Framework and Identity
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("EHSConnectionString")));
builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// Configure password policies
builder.Services.Configure<IdentityOptions>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequireUppercase = true;
    options.Password.RequiredLength = 8;
    options.Password.RequiredUniqueChars = 1;
    // 2FA tocken provider
    options.Tokens.AuthenticatorTokenProvider = TokenOptions.DefaultAuthenticatorProvider;
    options.SignIn.RequireConfirmedEmail = true;
});

// Configure JWT authentication
// Configure JWT settings
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
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(builder.Configuration["Jwt:SecretKey"]))
    };
});

// Configure Serilog
builder.Host.UseSerilog((context, config) =>
{
    config
        .ReadFrom.Configuration(context.Configuration)
        .WriteTo.Console();
});

// Add rate limiting
//builder.Services.AddScoped<RateLimitingMiddleware>();

// send 2FA code
builder.Services.AddSingleton<IEmailSender, EmailSender>();

// Add CAPTCHA service
builder.Services.AddSingleton<IReCaptchaService, ReCaptchaService>();




builder.Services.AddControllers(options =>
{
    options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute());
});
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
else
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles(); // Enable serving static files
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.UseMiddleware<RateLimitingMiddleware>(); // Register the rate limiting middleware

app.MapControllers();

app.Run();
