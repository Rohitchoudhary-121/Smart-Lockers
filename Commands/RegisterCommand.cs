using Microsoft.VisualBasic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel;
using System.Text.Json.Serialization;

namespace WebApplication1.Commands
{
    public class RegisterCommand : IHasCustomerId
    {
        [Required]
        public string FirstName { get; set; }
        [Required]
        public string LastName { get; set; }
        [Required]
        public string Email { get; set; }

        public bool IsMarketingSelected { get; set; }

        public string Password { get; set; }

        public string Phone { get; set; }

        public int SubscriptionId { get; set; }

        public bool AutoGenerate { get; set; }

        public List<string> UserRoles { get; set; }

        public string CustomerId { get; set; }

        public string Language { get; set; } = Constants.LanguageCodeDutch;

        public List<WaysOfIdentification> WaysOfIdentifications { get; set; }

        public Dictionary<WaysOfIdentification, string> Identity { get; set; }

        public string QrCode { get; set; }

        public string HouseNumber { get; set; }

        [DefaultValue(false)]
        public bool IsAzureADUser { get; set; }

        public string CustomerIdentificationId { get; set; }

        /// <summary>
        /// Scenarios
        /// </summary>
        [JsonIgnore]
        public Scenarios Scenarios { get; set; }

        public bool ResetPin { get; set; }

        /// <summary>
        /// Determines If Flex Use Is Supported
        /// </summary>
        public bool HasFlexUseSceneario
        {
            get => (Scenarios & Scenarios.Flex) != Scenarios.None;
            set
            {
                if (value)
                    Scenarios |= Scenarios.Flex;
                else
                    Scenarios &= ~Scenarios.Flex;
            }
        }

        /// <summary>
        /// Determines If Assigned Use Is Supported
        /// </summary>
        public bool HasAssignedUseSceneario
        {
            get => (Scenarios & Scenarios.Assigned) != Scenarios.None;
            set
            {
                if (value)
                    Scenarios |= Scenarios.Assigned;
                else
                    Scenarios &= ~Scenarios.Assigned;
            }
        }

        /// <summary>
        /// Detemines If FlexAnonymous Use Is Supported
        /// </summary>
        public bool HasFlexAnonymousUseSceneario
        {
            get => (Scenarios & Scenarios.FlexAnonymous) != Scenarios.None;
            set
            {
                if (value)
                    Scenarios |= Scenarios.FlexAnonymous;
                else
                    Scenarios &= ~Scenarios.FlexAnonymous;
            }
        }

        /// <summary>
        /// Detemines If Rental Use Is Supported
        /// </summary>
        public bool HasRentalUseSceneario
        {
            get => (Scenarios & Scenarios.Rental) != Scenarios.None;
            set
            {
                if (value)
                    Scenarios |= Scenarios.Rental;
                else
                    Scenarios &= ~Scenarios.Rental;
            }
        }

        /// <summary>
        /// Detemines If Distribution Use Is Supported
        /// </summary>
        public bool HasDistributionUseSceneario
        {
            get => (Scenarios & Scenarios.Distribution) != Scenarios.None;
            set
            {
                if (value)
                    Scenarios |= Scenarios.Distribution;
                else
                    Scenarios &= ~Scenarios.Distribution;
            }
        }

        /// <summary>
        /// Detemines If Drop-Off & Pick-Up Is Supported
        /// </summary>
        public bool HasDropOffPickUpSceneario
        {
            get => (Scenarios & Scenarios.DropOffPickUp) != Scenarios.None;
            set
            {
                if (value)
                    Scenarios |= Scenarios.DropOffPickUp;
                else
                    Scenarios &= ~Scenarios.DropOffPickUp;
            }
        }

        public bool HasDropOffPickUpAnonymousSceneario
        {
            get => (Scenarios & Scenarios.DropoffPickupAnonymous) != Scenarios.None;
            set
            {
                if (value)
                    Scenarios |= Scenarios.DropoffPickupAnonymous;
                else
                    Scenarios &= ~Scenarios.DropoffPickupAnonymous;
            }
        }

        public bool IsPIMUser { get; set; }
    }
}
