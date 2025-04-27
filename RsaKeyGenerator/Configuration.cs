using System.Configuration.Annotation;

namespace RsaKeyGenerator
{
	public class Configuration
	{
		[Property(PropertyType.INT, DefaultValue = "2048")]
		public int? KeySize { get; set; }

		[Property(PropertyType.STRING, required: true)]
		public string PubKeyFilePath { get; set; } = null!;

		[Property(PropertyType.STRING, required: true)]
		public string PrivKeyFilePath { get; set; } = null!;

		[Property(PropertyType.BOOL, DefaultValue = "false")]
		public bool? UsePassword { get; set; }

		[Property(PropertyType.STRING, required: true, Parent = "UsePassword")]
		public string Password { get; set; } = null!;

		[Property(PropertyType.BOOL, DefaultValue = "false")]
		public bool? PrivSingleLine { get; set; }

		[Property(PropertyType.BOOL, DefaultValue = "false")]
		public bool? PubSingleLine { get; set; }
	}
}
