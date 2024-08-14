namespace ehs_API.Modal.DTO
{   
        public class RegisterRequest
        {
            public string Name { get; set; }
            public string Email { get; set; }
            public string Password { get; set; }
            public string ConfirmPassword { get; set; }
            public string MobileNumber { get; set; }
            public string Resume { get; set; } // Store the URL or file path in the database    
            public bool TermsAccepted { get; set; }
        }   

}
