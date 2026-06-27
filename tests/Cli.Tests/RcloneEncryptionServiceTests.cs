using Xunit;
using FluentAssertions;
using Cli;

namespace Cli.Tests;

public class RcloneEncryptionServiceTests
{
    [Fact]
    public void Encrypt_EncryptsPlaintext()
    {
        var service = new RcloneEncryptionService();
        var plaintext = "Hello, World!"u8.ToArray();
        var password = "TestPassword123!";

        var encrypted = service.Encrypt(plaintext, password);

        encrypted.Should().NotBeEmpty();
        encrypted.Length.Should().BeGreaterThan(plaintext.Length);
    }

    [Fact]
    public void Encrypt_IncludesRcloneHeader()
    {
        var service = new RcloneEncryptionService();
        var plaintext = "Test"u8.ToArray();
        var password = "Password";

        var encrypted = service.Encrypt(plaintext, password);

        var header = System.Text.Encoding.ASCII.GetString(encrypted, 0, 6);
        header.Should().Be(RcloneFormat.HeaderMagic);
    }

    [Fact]
    public void Decrypt_DecryptsEncryptedData()
    {
        var service = new RcloneEncryptionService();
        var plaintext = "Hello, World!"u8.ToArray();
        var password = "TestPassword123!";

        var encrypted = service.Encrypt(plaintext, password);
        var decrypted = service.Decrypt(encrypted, password);

        decrypted.Should().Equal(plaintext);
    }

    [Fact]
    public void Decrypt_WithWrongPassword_Throws()
    {
        var service = new RcloneEncryptionService();
        var plaintext = "Secret Data"u8.ToArray();
        var password = "CorrectPassword";
        var wrongPassword = "WrongPassword";

        var encrypted = service.Encrypt(plaintext, password);

        var action = () => service.Decrypt(encrypted, wrongPassword);
        action.Should().Throw<Exception>();
    }

    [Fact]
    public void Encrypt_WithCustomSalt_UsesSalt()
    {
        var service = new RcloneEncryptionService();
        var plaintext = "Test Data"u8.ToArray();
        var password = "Password";
        var salt = new byte[16] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

        var encrypted1 = service.Encrypt(plaintext, password, salt);
        var encrypted2 = service.Encrypt(plaintext, password, salt);

        encrypted1.Length.Should().Be(encrypted2.Length);
    }

    [Fact]
    public void Decrypt_WithProvidedSalt_Works()
    {
        var service = new RcloneEncryptionService();
        var plaintext = "Test Data"u8.ToArray();
        var password = "Password";
        var salt = new byte[16];
        using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
        {
            rng.GetBytes(salt);
        }

        var encrypted = service.Encrypt(plaintext, password, salt);
        var decrypted = service.Decrypt(encrypted, password);

        decrypted.Should().Equal(plaintext);
    }

    [Fact]
    public void EncryptDecrypt_WithLargeFile_Works()
    {
        var service = new RcloneEncryptionService();
        var plaintext = new byte[1024 * 1024];
        using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
        {
            rng.GetBytes(plaintext);
        }
        var password = "LargeFilePassword";

        var encrypted = service.Encrypt(plaintext, password);
        var decrypted = service.Decrypt(encrypted, password);

        decrypted.Should().Equal(plaintext);
    }

    [Fact]
    public void EncryptFilename_EncryptsFilename()
    {
        var service = new RcloneEncryptionService();
        var filename = "secret.txt";
        var password = "FilePassword";

        var encrypted = service.EncryptFilename(filename, password);

        encrypted.Should().NotBeEmpty();
        encrypted.Should().NotContain(filename);
    }

    [Fact]
    public void DecryptFilename_DecryptsEncryptedFilename()
    {
        var service = new RcloneEncryptionService();
        var filename = "confidential_document.pdf";
        var password = "FileCryptPassword";

        var encrypted = service.EncryptFilename(filename, password);
        var decrypted = service.DecryptFilename(encrypted, password);

        decrypted.Should().Be(filename);
    }

    [Fact]
    public void EncryptFilename_WithBase64Encoding()
    {
        var service = new RcloneEncryptionService();
        var filename = "test.txt";
        var password = "Pass";

        var base32 = service.EncryptFilename(filename, password, encoding: "base32");
        var base64 = service.EncryptFilename(filename, password, encoding: "base64");

        base32.Should().NotBeEmpty();
        base64.Should().NotBeEmpty();
        base32.Should().NotBe(base64);
    }

    [Fact]
    public void EncryptFilename_WithHexEncoding()
    {
        var service = new RcloneEncryptionService();
        var filename = "myfile.doc";
        var password = "HexPass";

        var hex = service.EncryptFilename(filename, password, encoding: "hex");

        hex.Should().NotBeEmpty();
        hex.Should().MatchRegex("^[0-9A-Fa-f]+$");
    }

    [Fact]
    public void DecryptFilename_WithDifferentEncodings()
    {
        var service = new RcloneEncryptionService();
        var filename = "report.xlsx";
        var password = "ReportPass";

        foreach (var encoding in new[] { "base32", "base64", "hex" })
        {
            var encrypted = service.EncryptFilename(filename, password, encoding: encoding);
            var decrypted = service.DecryptFilename(encrypted, password, encoding: encoding);
            decrypted.Should().Be(filename);
        }
    }

    [Fact]
    public void KeyDerivation_SamePasswordAndSalt_SameKey()
    {
        var derivation = new KeyDerivationService();
        var password = "ConsistentPassword";
        var salt = new byte[16] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

        var (key1, _) = derivation.DeriveKey(password, salt);
        var (key2, _) = derivation.DeriveKey(password, salt);

        key1.Should().Equal(key2);
    }

    [Fact]
    public void Decrypt_InvalidHeader_Throws()
    {
        var service = new RcloneEncryptionService();
        var badData = new byte[50];
        System.Text.Encoding.ASCII.GetBytes("BADHEADER").CopyTo(badData, 0);

        var action = () => service.Decrypt(badData, "password");
        action.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Decrypt_ShortData_Throws()
    {
        var service = new RcloneEncryptionService();
        var tooShort = new byte[5];

        var action = () => service.Decrypt(tooShort, "password");
        action.Should().Throw<ArgumentException>();
    }
}
