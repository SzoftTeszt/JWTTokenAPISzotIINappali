namespace JWTTokenAPI.Models
{
    public class LoggedUser
    {
        public ApplicationUser User { get; set; }
        public string Token { get; set; }

        public LoggedUser(ApplicationUser user, string token)
        {
            User = user;
            Token = token;
        }
    }
}
