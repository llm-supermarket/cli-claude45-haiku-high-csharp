using System.Security.Cryptography;

namespace Cli;

public class KeyDerivationService
{
    private const int KeyBytes = 32;

    public (byte[] Key, byte[] Salt) DeriveKey(string password, byte[]? salt = null)
    {
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException("Password cannot be empty", nameof(password));

        var passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
        salt ??= RandomNumberGenerator.GetBytes(RcloneFormat.SaltSize);

        var key = Rfc2898DeriveBytes.Pbkdf2(
            passwordBytes,
            salt,
            iterations: 1,
            hashAlgorithm: HashAlgorithmName.SHA256,
            outputLength: KeyBytes);

        return (key, salt);
    }
}
