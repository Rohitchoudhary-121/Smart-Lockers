using Repository;

namespace Olssen.Slp.Handlers.Account
{
    public class UpdateAndSetupUserHandler : HandlerBase<UpdateAndSetupUserCommand, GenericBaseResult<SetupUserResult>, UpdateAndSetupUserHandler>
    {
        private readonly IAccountRepository _accountRepository;
        private readonly ISmartHubUserRepository _smartHubUserRepository;

        public UpdateAndSetupUserHandler(IAccountRepository accountRepository, ISmartHubUserRepository smartHubUserRepository, IMapper mapper, ILogger<UpdateAndSetupUserHandler> logger) : base(mapper, logger)
            => (_accountRepository, _smartHubUserRepository) = (accountRepository, smartHubUserRepository);

        protected override async Task<GenericBaseResult<SetupUserResult>> OnHandleRequest(UpdateAndSetupUserCommand request, CancellationToken cancellationToken)
        {
            try
            {
                var registrationResult = await _accountRepository.UpdateAndSetupUser(request);

                var setupPinResult = await _smartHubUserRepository.GetPin(registrationResult.User.Id);

                var result = new SetupUserResult { Email = registrationResult.User.Email, Pin = setupPinResult, Lockers = await registrationResult.AssignedLockers.ProjectToListAsync<AssignedLockerResult>(MapperConfiguration) };

                return new GenericBaseResult<SetupUserResult>(result) { Message = "User Updated Successfully" };
            }
            catch (Exception ex)
            {
                var result = new GenericBaseResult<SetupUserResult>(null);
                result.AddExceptionLog(ex);
                result.Message = ex.Message;
                return result;
            }
        }
    }
}
