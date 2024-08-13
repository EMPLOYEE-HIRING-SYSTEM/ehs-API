using Microsoft.AspNetCore.Identity;

namespace ehs_API.Data
{
    public class ApplicationUser : IdentityUser
    {
        public string Name { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public string ConfirmPassword { get; set; }
        public string MobileNumber { get; set; }
        public IFormFile Resume { get; set; } // For handling file uploads
        public bool TermsAccepted { get; set; } // Checkbox for terms and conditions
    }
}
