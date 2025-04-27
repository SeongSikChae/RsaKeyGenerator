using CommandLine;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System.Configuration;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.X509;

namespace RsaKeyGenerator
{
	internal class Program
	{
		internal sealed class CmdMain
		{
			[Option("config", Required = true, HelpText = "config file path")]
			public string ConfigFilePath { get; set; } = null!;
		}

		static async Task Main(string[] args)
		{
			ParserResult<CmdMain> result = await Parser.Default.ParseArguments<CmdMain>(args)
				.WithParsedAsync(async cmdMain =>
				{
					await Generate(cmdMain);
				});

			await result.WithNotParsedAsync(async errors =>
			{
				await Task.CompletedTask;
			});
		}

		static async Task Generate(CmdMain cmdMain)
		{
			YamlDotNet.Serialization.Deserializer deserializer = new YamlDotNet.Serialization.Deserializer();
			string str = File.ReadAllText(cmdMain.ConfigFilePath);
			Configuration configuration = deserializer.Deserialize<Configuration>(str);
			ConfigurationValidator.Validate(configuration);
			ArgumentNullException.ThrowIfNull(configuration.KeySize);
			ArgumentNullException.ThrowIfNull(configuration.PrivSingleLine);
			ArgumentNullException.ThrowIfNull(configuration.PubSingleLine);
			ArgumentNullException.ThrowIfNull(configuration.UsePassword);

			SecureRandom secureRandom = new SecureRandom();
			IAsymmetricCipherKeyPairGenerator generator = new RsaKeyPairGenerator();
			KeyGenerationParameters parameters = new KeyGenerationParameters(secureRandom, configuration.KeySize.Value);
			generator.Init(parameters);

			Console.WriteLine($"key pair generate... : {configuration.KeySize.Value}");

			AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();

			PemObject pemObject;
			if (configuration.UsePassword.Value)
			{
				Org.BouncyCastle.OpenSsl.Pkcs8Generator g = new Org.BouncyCastle.OpenSsl.Pkcs8Generator(keyPair.Private, Org.BouncyCastle.OpenSsl.Pkcs8Generator.PbeSha1_3DES);
				g.Password = configuration.Password.ToCharArray();
				pemObject = g.Generate();
			}
			else
			{
				PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private);
				byte[] privKeyBytes = privateKeyInfo.GetEncoded();
				pemObject = new PemObject("PRIVATE KEY", privKeyBytes);
			}


			FileInfo privateKeyFileInfo = new FileInfo(configuration.PrivKeyFilePath);
			if (privateKeyFileInfo.Directory is not null && !privateKeyFileInfo.Directory.Exists)
				privateKeyFileInfo.Directory.Create();
			using (FileStream stream = new FileStream(privateKeyFileInfo.FullName, FileMode.Create, FileAccess.Write))
			{
				using StreamWriter writer = new StreamWriter(stream);
				if (configuration.PrivSingleLine.Value)
				{
					writer.Write(Convert.ToBase64String(pemObject.Content));
				}
				else
				{
					using PemWriter pemWriter = new PemWriter(writer);
					pemWriter.WriteObject(pemObject);
				}
			}
			Console.WriteLine($"Private Key File Write : {privateKeyFileInfo.FullName}");

			SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);
			// 공개키 파일 출력
			PemObject publicPemObject = new PemObject("PUBLIC KEY", subjectPublicKeyInfo.GetEncoded());
			FileInfo publicKeyFileInfo = new FileInfo(configuration.PubKeyFilePath);
			if (publicKeyFileInfo.Directory is not null && !publicKeyFileInfo.Directory.Exists)
				publicKeyFileInfo.Directory.Create();
			using (FileStream stream = new FileStream(publicKeyFileInfo.FullName, FileMode.Create, FileAccess.Write))
			{
				using StreamWriter writer = new StreamWriter(stream);
				if (configuration.PubSingleLine.Value)
				{
					writer.Write(Convert.ToBase64String(subjectPublicKeyInfo.GetEncoded()));
				}
				else
				{
					using PemWriter pemWriter = new PemWriter(writer);
					pemWriter.WriteObject(publicPemObject);
				}
			}
			Console.WriteLine($"Public Key File Write : {publicKeyFileInfo.FullName}");

			await Task.CompletedTask;
		}
	}
}
