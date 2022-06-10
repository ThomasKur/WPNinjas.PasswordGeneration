using System;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace WPNinjas.PasswordGeneration
{
	public class PwService
	{
		private static Int32 GetRandomInt()
		{
			byte[] randomBytes = new byte[4];
			RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
			rng.GetBytes(randomBytes);
			Int32 randomInt = BitConverter.ToInt32(randomBytes, 0);
			rng.Dispose();
			return randomInt;
		}

		public static string GetRandomPassword(int len, string allowedCharacters = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz.:;,-_!?$%*=+&<>@#()23456789")
		{
			try
			{
				char[] possibleChars = allowedCharacters.ToCharArray();
				if (possibleChars.Length < 1)
				{
					throw new Exception("You must enter one or more possible characters.");
				}
				if (len < 4)
				{
					throw new Exception($"Please choose a password length. That length must be a value between 4 and {Int32.MaxValue}. Note: values above 1,000 might take a LONG TIME to process on some computers.");
				}

				StringBuilder builder = new StringBuilder();
				for (int i = 0; i < len; i++)
				{
					// Get our cryptographically random 32-bit integer & use as seed in Random class
					// NOTE: random value generated PER ITERATION, meaning that the System.Random class
					// is re-instantiated every iteration with a new, crytographically random numeric seed.
					int randInt32 = GetRandomInt();
					Random r = new Random(randInt32);

					int nextInt = r.Next(possibleChars.Length);
					char c = possibleChars[nextInt];
					builder.Append(c);

				}
				// return final constructed string
				return builder.ToString();
			}
			catch (Exception ex)
			{
				throw new Exception("An error has occurred while trying to generate random password!", ex);
			}
		}
		public static SecureString GetRandomPasswordSecure(int len, string allowedCharacters = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz.:;,-_!?$%*=+&<>@#()23456789")
		{
			try
			{
				char[] possibleChars = allowedCharacters.ToCharArray();
				if (possibleChars.Length < 1)
				{
					throw new Exception("You must enter one or more possible characters.");
				}
				if (len < 4)
				{
					throw new Exception($"Please choose a password length. That length must be a value between 4 and {Int32.MaxValue}. Note: values above 1,000 might take a LONG TIME to process on some computers.");
				}

				SecureString builder = new SecureString();

				for (int i = 0; i < len; i++)
				{
					// Get our cryptographically random 32-bit integer & use as seed in Random class
					// NOTE: random value generated PER ITERATION, meaning that the System.Random class
					// is re-instantiated every iteration with a new, crytographically random numeric seed.
					int randInt32 = GetRandomInt();
					Random r = new Random(randInt32);

					int nextInt = r.Next(possibleChars.Length);
					char c = possibleChars[nextInt];
					builder.AppendChar(c);

				}
				// return final constructed string
				return builder;
			}
			catch (Exception ex)
			{
				throw new Exception("An error has occurred while trying to generate random password!", ex);
			}
		}
		public static string GetRandomComplexPassword(int len, string allowedCharacters = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz.:;,-_!?$%*=+&<>@#()23456789") {
			string password = "";
			int count = 0;
			do
			{
				password = GetRandomPassword(len, allowedCharacters);
				count += 1;

			} while (CheckStrength(password) < 4 && count < 10);

			return password;
		}
		public static SecureString GetRandomComplexPasswordSecure(int len, string allowedCharacters = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz.:;,-_!?$%*=+&<>@#()23456789")
		{
			String password = null;
			int count = 0;
			do
			{
				password = GetRandomPassword(len, allowedCharacters);
				count += 1;
				
			} while (CheckStrength(password) < 4 && count < 10);
			
			var secStr = new System.Security.SecureString(); secStr.Clear();
			foreach (char c in password.ToCharArray())
			{
				secStr.AppendChar(c);
			}
			return secStr;
		}

		public static int CheckStrength(string password)
		{
			int score = 0;

			if (password.Length < 1)
				return 0;
			if (password.Length < 4)
				return 0;

			if (password.Length >= 8)
				score++;
			if (password.Length >= 12)
				score++;
			if (Regex.Match(password, @"/\d+/", RegexOptions.ECMAScript).Success)
				score++;
			if (Regex.Match(password, @"/[a-z]/", RegexOptions.ECMAScript).Success &&
			  Regex.Match(password, @"/[A-Z]/", RegexOptions.ECMAScript).Success)
				score++;
			if (Regex.Match(password, @"/.[!,@,#,$,%,^,&,*,?,_,~,-,£,(,)]/", RegexOptions.ECMAScript).Success)
				score++;

			return score;
		}

	}
}
