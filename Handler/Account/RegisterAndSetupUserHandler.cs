using Repository;

namespace Olssen.Slp.Handlers.Account
{
    public class RegisterAndSetupUserHandler : HandlerBase<RegisterAndSetupUserCommand, GenericBaseResult<SetupUserResult>, RegisterAndSetupUserHandler>
    {
        private readonly IAccountRepository _accountRepository;
        private readonly ISmartHubUserRepository _smartHubUserRepository;

        public RegisterAndSetupUserHandler(IAccountRepository accountRepository, ISmartHubUserRepository smartHubUserRepository, IMapper mapper, ILogger<RegisterAndSetupUserHandler> logger) : base(mapper, logger)
            => (_accountRepository, _smartHubUserRepository) = (accountRepository, smartHubUserRepository);

        protected override async Task<GenericBaseResult<SetupUserResult>> OnHandleRequest(RegisterAndSetupUserCommand request, CancellationToken cancellationToken)
        {
            try
            {
                var registrationResult = await _accountRepository.RegisterAndSetupUser(request, request.IsExternal);

                var setupPinResult = await _smartHubUserRepository.GetPin(registrationResult.User.Id);

                var result = new SetupUserResult
                {
                    UserId = registrationResult.User.Id,
                    Email = registrationResult.User.Email,
                    Pin = setupPinResult,
                    Lockers = await registrationResult.AssignedLockers.ProjectToListAsync<AssignedLockerResult>(MapperConfiguration)
                };

                return new GenericBaseResult<SetupUserResult>(result) { ResponseStatusCode = System.Net.HttpStatusCode.Created, Message = $"{result.Email} Registered Successfully" };
            }
            catch (Exception ex)
            {
                var result = new GenericBaseResult<SetupUserResult>(null);
                result.AddExceptionLog(ex);
                result.Message = ex.Message;
                result.ResponseStatusCode = System.Net.HttpStatusCode.BadRequest;
                return result;
            }
        }
    }
}
