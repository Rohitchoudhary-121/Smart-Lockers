using System.Text.Json.Serialization;
using WebApplication1.Common;

namespace WebApplication1.Commands
{
    public class RegisterAndSetupUserCommand : RegisterCommand, IRequest<GenericBaseResult<SetupUserResult>>
    {
        public List<string> LockerWallIds { get; set; }
        public List<AssignLockerToUser> AssignedLockers { get; set; }
        public List<string> Sites { get; set; }
        public List<string> RfIds { get; set; }
        public bool IsExternal { get; set; }
        [JsonIgnore]
        public string UserId { get; set; }
    }
}
