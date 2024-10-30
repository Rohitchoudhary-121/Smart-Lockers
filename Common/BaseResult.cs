using System.ComponentModel.DataAnnotations;
using System.Net;
using System.Text.Json.Serialization;

namespace WebApplication1.Common
{
    public class BaseResult
    {
        public static bool IsInDebuggingMode { get; set; }
        public bool IsSuccess
         => (ResponseStatusCode == HttpStatusCode.OK || ResponseStatusCode == HttpStatusCode.Created || ResponseStatusCode == HttpStatusCode.Accepted);

        public string Message { get; set; }

        public IList<string> Errors { get; set; }

        [JsonIgnore]
        public HttpStatusCode ResponseStatusCode { get; set; } = HttpStatusCode.OK;

        public void AddExceptionLog(Exception ex)
        {
            if (ResponseStatusCode == HttpStatusCode.OK)
                ResponseStatusCode = HttpStatusCode.BadRequest;

            // It is really bad idea to show exceptions in production.
            if (IsInDebuggingMode || ex is ValidationException || ex is ArgumentNullException || ex is InvalidOperationException)
            {
                if (Errors == null) // Initialize if needed
                    Errors = new List<string>();

                Errors.Add(ex.Message);
                if (ex.InnerException != null)
                    AddExceptionLog(ex.InnerException);
            }
        }
    }
}
