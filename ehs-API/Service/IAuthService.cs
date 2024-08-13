using ehs_API.Modal.DTO;

namespace ehs_API.Service
{
    public interface IAuthService
    {
        Task<string> RegisterUserAsync(RegisterRequest request);
        Task<string> LoginUserAsync(LoginRequest request);
    }
}
