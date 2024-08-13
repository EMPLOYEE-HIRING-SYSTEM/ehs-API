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

        public AuthService(UserManager<ApplicationUser> userManager, IMapper mapper, ILogger<AuthService> logger, IConfiguration configuration, Microsoft.AspNetCore.Hosting.IHostingEnvironment hostingEnvironment)
        {
            _userManager = userManager;
            _mapper = mapper;
            _logger = logger;
            _configuration = configuration;
            _hostingEnvironment = hostingEnvironment;
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
                    // Handle file upload
                    if (request.Resume != null)
                    {
                        var resumeFilePath = Path.Combine(_hostingEnvironment.WebRootPath, "uploads", request.Resume.FileName);
                        using (var stream = new FileStream(resumeFilePath, FileMode.Create))
                        {
                            await request.Resume.CopyToAsync(stream);
                        }
                        _logger.LogInformation($"Resume uploaded for user: {user.UserName}");
                    }

                    _logger.LogInformation($"User registered successfully: {user.UserName}");
                    return "User registered successfully.";
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
