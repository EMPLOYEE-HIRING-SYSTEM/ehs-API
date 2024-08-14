using ehs_API.Modal.DTO;
using ehs_API.Service;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace ehs_API.Controllers
{
    [AutoValidateAntiforgeryToken] // CSRF protection
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly IReCaptchaService _reCaptchaService;
        private readonly ILogger<AuthController> _logger;

        public AuthController(IAuthService authService, IReCaptchaService reCaptchaService, ILogger<AuthController> logger)
        {
            _authService = authService;
            _reCaptchaService = reCaptchaService;
            _logger = logger;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromForm] RegisterRequest request)
        {
            // Verify reCAPTCHA
            var recaptchaResponse = Request.Form["g-recaptcha-response"];
            var isCaptchaValid = await _reCaptchaService.VerifyAsync(recaptchaResponse);
            if (!isCaptchaValid)
            {
                _logger.LogWarning("Invalid reCAPTCHA response.");
                return BadRequest("Invalid reCAPTCHA response.");
            }
            try
            {                
                var result = await _authService.RegisterUserAsync(request);
                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred during user registration.");
                return StatusCode(500, "Internal server error.");
            }
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromForm] LoginRequest request)
        {
            // Extract reCAPTCHA response from the request
            var recaptchaResponse = Request.Form["g-recaptcha-response"];
            if (!await _reCaptchaService.VerifyAsync(recaptchaResponse))
            {
                _logger.LogWarning("Invalid reCAPTCHA response during login.");
                return BadRequest("Invalid reCAPTCHA response.");
            }

            try
            {
                var token = await _authService.LoginUserAsync(request);
                return Ok(new { Token = token });
            }
            catch (UnauthorizedAccessException ex)
            {
                _logger.LogWarning(ex, "Unauthorized login attempt.");
                return Unauthorized("Invalid login attempt.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred during user login.");
                return StatusCode(500, "Internal server error.");
            }
        }
    }
}
