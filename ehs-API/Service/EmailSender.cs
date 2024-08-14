using System.Net.Mail;
using System.Net;

namespace ehs_API.Service
{
    public class EmailSender : IEmailSender
    {
        private readonly SmtpClient _smtpClient;
        private readonly string _fromEmail;

        public EmailSender(IConfiguration configuration)
        {
            var smtpSettings = configuration.GetSection("Smtp");
            _smtpClient = new SmtpClient
            {
                Host = smtpSettings["Server"],
                Port = int.Parse(smtpSettings["Port"]),
                Credentials = new NetworkCredential(smtpSettings["Username"], smtpSettings["Password"]),
                EnableSsl = true
            };
            _fromEmail = smtpSettings["FromEmail"];
        }

        public async Task SendEmailAsync(string email, string subject, string message)
        {
            var mailMessage = new MailMessage
            {
                From = new MailAddress(_fromEmail),
                Subject = subject,
                Body = message,
                IsBodyHtml = true
            };
            mailMessage.To.Add(email);

            await _smtpClient.SendMailAsync(mailMessage);
        }
    }
}
