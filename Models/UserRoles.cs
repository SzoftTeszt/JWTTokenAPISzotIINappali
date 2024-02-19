namespace JWTTokenAPI.Models
{
    public class UserRoles
    {
        public const string Admin = "Admin";
        public const string User = "User";
        public const string SAdmin = "SAdmin";
        public const string AdministratorOrSuperAdministrator = Admin + "," + SAdmin;
    }
}
