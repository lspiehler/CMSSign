using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;

namespace CMSSign
{
    class Program
    {
        public static byte[] ToByteArray(String hexString)
        {
            byte[] retval = new byte[hexString.Length / 2];
            for (int i = 0; i < hexString.Length; i += 2)
                retval[i / 2] = Convert.ToByte(hexString.Substring(i, 2), 16);
            return retval;
        }

        static byte[] SignFile(byte[] fileContent, X509Certificate2 verificationCert, string[] args)
        {
            //System.Console.WriteLine(verificationCert.Subject);
            ContentInfo contentInfo = new ContentInfo(fileContent);
            SignedCms signedCMS = new SignedCms(contentInfo);
            CmsSigner cmsSigner = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, verificationCert)
            {
                IncludeOption = X509IncludeOption.None
            };

            cmsSigner.DigestAlgorithm = new Oid("1.3.14.3.2.26"); //SHA1
            //cmsSigner.DigestAlgorithm = new Oid(" 2.16.840.1.101.3.4.2.1"); //SHA256

            //cmsSigner.SignedAttributes.Add(new Pkcs9SigningTime());
            cmsSigner.SignedAttributes.Add(new AsnEncodedData(new Oid("2.16.840.1.113733.1.9.2"), new DerPrintableString("3", true).GetDerEncoded()));
            if (args.Length == 10)
            {
                //System.Console.WriteLine("We're here");
                cmsSigner.SignedAttributes.Add(new AsnEncodedData(new Oid("2.16.840.1.113733.1.9.3"), new DerPrintableString(args[7].ToString(), true).GetDerEncoded()));
                cmsSigner.SignedAttributes.Add(new AsnEncodedData(new Oid("2.16.840.1.113733.1.9.4"), new DerPrintableString(args[8]).GetDerEncoded()));
                cmsSigner.SignedAttributes.Add(new AsnEncodedData(new Oid("1.3.6.1.4.1.311.21.33"), new DerPrintableString(args[9]).GetDerEncoded()));
                cmsSigner.SignedAttributes.Add(new AsnEncodedData(new Oid("2.16.840.1.113733.1.9.5"), new DerOctetString(ToByteArray(args[3])).GetDerEncoded()));
                cmsSigner.SignedAttributes.Add(new AsnEncodedData(new Oid("2.16.840.1.113733.1.9.6"), new DerOctetString(ToByteArray(args[4])).GetDerEncoded()));
                cmsSigner.SignedAttributes.Add(new AsnEncodedData(new Oid("2.16.840.1.113733.1.9.7"), new DerPrintableString(args[5], true).GetDerEncoded()));
            }
            else
            {
                cmsSigner.SignedAttributes.Add(new AsnEncodedData(new Oid("2.16.840.1.113733.1.9.3"), new DerPrintableString("0", true).GetDerEncoded()));
                cmsSigner.SignedAttributes.Add(new AsnEncodedData(new Oid("1.3.6.1.4.1.311.21.38"), new DerUtf8String("Issued").GetDerEncoded()));
                cmsSigner.SignedAttributes.Add(new AsnEncodedData(new Oid("2.16.840.1.113733.1.9.5"), new DerOctetString(ToByteArray(args[3])).GetDerEncoded()));
                cmsSigner.SignedAttributes.Add(new AsnEncodedData(new Oid("2.16.840.1.113733.1.9.6"), new DerOctetString(ToByteArray(args[4])).GetDerEncoded()));
                cmsSigner.SignedAttributes.Add(new AsnEncodedData(new Oid("2.16.840.1.113733.1.9.7"), new DerPrintableString(args[5], true).GetDerEncoded()));
            }

            //System.Console.WriteLine(cmsSigner.Certificate.PrivateKey);
            try
            {
                signedCMS.ComputeSignature(cmsSigner, false);
            }
            catch (Exception e)
            {
                System.Console.WriteLine(e.ToString());
                return new byte[0];
            }
            //System.Console.WriteLine("got here 2");
            byte[] encoded = signedCMS.Encode();
            //System.Console.WriteLine("got here 3");

            return encoded;
        }

        static int TestFunc(string[] args)
        {
            if (args.Length == 0)
            {
                System.Console.WriteLine("Please enter a numeric argument.");
                return 1;
            }
            else
            {
                if (File.Exists(args[0]))
                {
                    System.Console.WriteLine(args[2]);
                    byte[] fileBytes = File.ReadAllBytes(args[2]);
                    //X509Certificate x509 = new X509Certificate.CreateFromCertFile("C:\\Users\\ls12943\\Desktop\\ca.key");
                    //x509.CreateFromCertFile(certBytes);
                    //byte[] fileBytes = File.ReadAllBytes(args[0]);
                    X509Certificate2 certificate = new X509Certificate2(args[0], args[1], X509KeyStorageFlags.PersistKeySet);
                    //X509Certificate2 certificate = new X509Certificate2(temp.Export(X509ContentType.Pfx));
                    byte[] encoded = SignFile(fileBytes, certificate, args);

                    using (FileStream stream = new FileStream(args[6], FileMode.Create))
                    {
                        using (BinaryWriter writer = new BinaryWriter(stream))
                        {
                            writer.Write(encoded);
                            writer.Close();
                        }
                    }
                }
                return 0;
            }
        }

        static void Main(string[] args)
        {
            TestFunc(args);
            //System.Console.ReadLine();
        }
    }
}
