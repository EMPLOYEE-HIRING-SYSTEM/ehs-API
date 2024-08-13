namespace ehs_API.Modal.DTO
{   
        public class RegisterRequest
        {
            public string Name { get; set; }
            public string Email { get; set; }
            public string Password { get; set; }
            public string ConfirmPassword { get; set; }
            public string MobileNumber { get; set; }
            public IFormFile Resume { get; set; }
            public bool TermsAccepted { get; set; }
        }   

}
