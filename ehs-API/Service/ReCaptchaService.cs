namespace ehs_API.Service
{
    public class ReCaptchaService : IReCaptchaService
    {
        private readonly IConfiguration _configuration;
        private readonly HttpClient _httpClient;

        public ReCaptchaService(IConfiguration configuration)
        {
            _configuration = configuration;
            _httpClient = new HttpClient();
        }

        public async Task<bool> VerifyAsync(string responseToken)
        {
            var secretKey = _configuration["ReCaptcha:SecretKey"];
            var response = await _httpClient.PostAsync($"https://www.google.com/recaptcha/api/siteverify?secret={secretKey}&response={responseToken}", null);
            var jsonResponse = await response.Content.ReadAsStringAsync();
            dynamic result = Newtonsoft.Json.JsonConvert.DeserializeObject(jsonResponse);
            return result.success == "true";
        }
    }
}
