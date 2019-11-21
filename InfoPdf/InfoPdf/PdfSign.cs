using iTextSharp.text;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using SysX509 = System.Security.Cryptography.X509Certificates;

namespace InfoRegistroDB.PDF
{
    public class PdfFirmaDigital
    {

        public static bool SignHashed(string Source, string Target, SysX509.X509Certificate2 Certificate)
        {
            return SignHashed(Source, Target, Certificate, "", "", true, false, DateTime.Now.ToShortDateString());
        }
        public static bool SignHashed(string Source, string Target, SysX509.X509Certificate2 Certificate, string Reason, string Location, bool AddVisibleSign, bool AddTimeStamp, string strTSA)
        {
            PdfReader objReader = null;
            PdfStamper objStamper = null;
            try
            {
                X509CertificateParser objCP = new Org.BouncyCastle.X509.X509CertificateParser();
                X509Certificate[] objChain = new X509Certificate[] { objCP.ReadCertificate(Certificate.RawData) };

                IList<ICrlClient> crlList = new List<ICrlClient>();
                crlList.Add(new CrlClientOnline(objChain));

                objReader = new PdfReader(Source);
                objStamper = PdfStamper.CreateSignature(objReader, new FileStream(Target, FileMode.Create), '\0', null, true);

                // Creamos la apariencia
                PdfSignatureAppearance signatureAppearance = objStamper.SignatureAppearance;
                signatureAppearance.Reason = "Inforegistro, S.L.";
                //signatureAppearance.Location = Location;

                // Custom signature appearance text
                var font = FontFactory.GetFont("Times New Roman", 11, iTextSharp.text.Font.BOLDITALIC, BaseColor.DARK_GRAY);
                signatureAppearance.Layer2Font = font;
                signatureAppearance.Layer2Text = "Firmado digitalmente por \r\nInforegistro, S.L.\r\nFecha  " + DateTime.Now.ToShortDateString();
                var rectangle = new Rectangle(350, 30, 500, 120);

                // Si está la firma visible:
                if (AddVisibleSign)
                    signatureAppearance.SetVisibleSignature(rectangle, 2, "Inforegistro");

                ITSAClient tsaClient = null;
                IOcspClient ocspClient = null;

                // Creating the signature
                IExternalSignature externalSignature = new X509Certificate2Signature(Certificate, "SHA-1");
                MakeSignature.SignDetached(signatureAppearance, externalSignature, objChain, crlList, ocspClient, tsaClient, 0, CryptoStandard.CMS);
                return File.Exists(Target);

            }
            catch (Exception ex)
            {
                throw ex;
            }
            finally
            {
                if (objReader != null)
                    objReader.Close();
                if (objStamper != null)
                    objStamper.Close();
            }

        }
    }
}


