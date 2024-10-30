using Net.Codecrete.QrCodeGenerator;

namespace Keynius.Common
{
    public class QrCodeGenerator
    {
        public static byte[] GenerateQRCode(string qrText)
        {
            var qrCode = QrCode.EncodeText(qrText, QrCode.Ecc.High);
            byte[] png = qrCode.ToPng(10, 4);
            return png;
        }
    }
}
