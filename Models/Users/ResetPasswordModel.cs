using System.ComponentModel.DataAnnotations;

namespace JSegurosAPI.Models.Users
{
    public class ResetPasswordModel
    {

        [Required]
        public string Username { get; set; }

        [Required]
        public string NewPassword { get; set; }

        [Required]
        public string ConfirmPassword { get; set; }
    }
}
