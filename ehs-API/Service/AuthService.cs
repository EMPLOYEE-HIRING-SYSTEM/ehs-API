using AutoMapper;
using ehs_API.Data;
using ehs_API.Modal.DTO;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IO;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace ehs_API.Service
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IMapper _mapper;
        private readonly ILogger<AuthService> _logger;
        private readonly IConfiguration _configuration;
        private readonly Microsoft.AspNetCore.Hosting.IHostingEnvironment _hostingEnvironment;
        private readonly IEmailSender _emailSender;

        public AuthService(UserManager<ApplicationUser> userManager, IMapper mapper, ILogger<AuthService> logger, IConfiguration configuration, Microsoft.AspNetCore.Hosting.IHostingEnvironment hostingEnvironment, IEmailSender emailSender)
        {
            _userManager = userManager;
            _mapper = mapper;
            _logger = logger;
            _configuration = configuration;
            _hostingEnvironment = hostingEnvironment;
            _emailSender = emailSender;
        }

        public async Task<string> RegisterUserAsync(RegisterRequest request)
        {
            try
            {
                if (!request.TermsAccepted)
                {
                    _logger.LogWarning("User registration attempt without accepting terms and conditions.");
                    throw new Exception("You must accept the terms and conditions.");
                }

                if (request.Password != request.ConfirmPassword)
                {
                    _logger.LogWarning("User registration attempt with mismatched passwords.");
                    throw new Exception("Passwords do not match.");
                }

                var user = _mapper.Map<ApplicationUser>(request);
                var result = await _userManager.CreateAsync(user, request.Password);

                if (result.Succeeded)
                {
                    // Set up 2FA for the user
                    var token = await _userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultAuthenticatorProvider);
                    _logger.LogInformation($"2FA token generated for user: {user.UserName}");

                    // Send the 2FA token to the user via email or other means (implementation depends on your setup)
                    // For example, you might want to use a method like SendEmailAsync to send the token.
                    await SendTwoFactorTokenAsync(user.Email, token);

                    // Handle file upload
                    if (request.Resume != null)
                    {
                        var fileName = Path.GetFileName(request.Resume.FileName);
                        var filePath = Path.Combine(_hostingEnvironment.WebRootPath, "uploads", fileName);

                        using (var stream = new FileStream(filePath, FileMode.Create))
                        {
                            await request.Resume.CopyToAsync(stream);
                        }

                        // Store the URL or path in the database
                        user.ResumeUrl = $"/uploads/{fileName}";
                        await _userManager.UpdateAsync(user);

                        _logger.LogInformation($"Resume uploaded and saved for user: {user.UserName}");
                    }

                    _logger.LogInformation($"User registered successfully: {user.UserName}");
                    return "User registered successfully. Please check your email for a 2FA verification token.";
                }

                _logger.LogError("User registration failed: {Errors}", string.Join(", ", result.Errors.Select(e => e.Description)));
                throw new Exception("User registration failed.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred during user registration.");
                throw;
            }
        }

        // Example method to send the 2FA token
        private async Task SendTwoFactorTokenAsync(string email, string token)
        {
            var subject = "2FA Verification Code";
            var message = $"Your 2FA verification code is: <strong>{token}</strong>";
            try
            {
                await _emailSender.SendEmailAsync(email, subject, message);
                _logger.LogInformation($"2FA token sent to {email}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Failed to send 2FA token to {email}");
                throw;
            }
        }


        public async Task<string> LoginUserAsync(LoginRequest request)
        {
            try
            {
                var user = await _userManager.FindByNameAsync(request.Username);
                if (user != null && await _userManager.CheckPasswordAsync(user, request.Password))
                {
                    // Retrieve JWT settings from configuration
                    var secretKey = _configuration["Jwt:SecretKey"];
                    var issuer = _configuration["Jwt:Issuer"];
                    var audience = _configuration["Jwt:Audience"];

                    // Create JWT token
                    var tokenHandler = new JwtSecurityTokenHandler();
                    var key = Encoding.ASCII.GetBytes(secretKey);
                    var tokenDescriptor = new SecurityTokenDescriptor
                    {
                        Subject = new ClaimsIdentity(new[]
                        {
                            new Claim(ClaimTypes.NameIdentifier, user.Id),
                            new Claim(ClaimTypes.Email, user.Email)
                        }),
                        Expires = DateTime.UtcNow.AddHours(1),
                        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
                        Issuer = issuer,
                        Audience = audience
                    };
                    var token = tokenHandler.CreateToken(tokenDescriptor);
                    _logger.LogInformation($"User logged in successfully: {user.UserName}");
                    return tokenHandler.WriteToken(token);
                }

                _logger.LogWarning("Invalid login attempt for user: {Username}", request.Username);
                throw new UnauthorizedAccessException("Invalid login attempt.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred during user login.");
                throw;
            }
        }
    }
}
