using System.Text.Json.Serialization;
using WebApplication1.Common;

namespace WebApplication1.Commands
{
    public class UpdateAndSetupUserCommand : IRequest<GenericBaseResult<SetupUserResult>>
    {
        public UpdateAndSetupUserCommand(string id, string firstName, string lastName, string phone, string houseNumber, string customerIdentificationId) : base(id, firstName, lastName, phone, houseNumber, customerIdentificationId)
        {
        }
        public string Id { get; set; }
        public List<string> UserRoles { get; set; }
        public List<string> LockerWallIds { get; set; }
        public List<AssignLockerToUser> AssignedLockers { get; set; }
        public List<string> RfIds { get; set; }
        public List<string> BatteryLockPins { get; set; }
        public List<string> BatteryLockRfids { get; set; }
        public List<WaysOfIdentification> WaysOfIdentifications { get; set; }
        public List<string> Sites { get; set; }
        [JsonIgnore]
        public string UserId { get; set; }
        public string CustomerIdentificationId { get; set; }
    }
}
