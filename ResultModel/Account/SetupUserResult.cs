namespace WebApplication1.ResultModel.Account
{
    public class SetupUserResult
    {
        public string Email { get; set; }

        public int Pin { get; set; }

        public string UserId { get; set; }

        public string HouseNumber { get; set; }

        public List<AssignedLockerResult> Lockers { get; set; }
    }
}
