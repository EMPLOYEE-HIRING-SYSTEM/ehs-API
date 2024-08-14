namespace ehs_API.Service
{
    public interface IReCaptchaService
    {
        Task<bool> VerifyAsync(string responseToken);
    }
}
