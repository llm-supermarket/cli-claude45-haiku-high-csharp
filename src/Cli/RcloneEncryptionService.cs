using System.Security.Cryptography;

namespace Cli;

public class RcloneEncryptionService
{
    private readonly KeyDerivationService _keyDerivation;
    private const int AesIvSize = 12;

    public RcloneEncryptionService(KeyDerivationService? keyDerivation = null)
    {
        _keyDerivation = keyDerivation ?? new KeyDerivationService();
    }

    public byte[] Encrypt(byte[] plaintext, string password, byte[]? salt = null)
    {
        var (key, usedSalt) = _keyDerivation.DeriveKey(password, salt);

        using var aesGcm = new AesGcm(key, 16);
        var nonce = new byte[AesIvSize];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(nonce);
        }

        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];
        aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);

        var result = new byte[
            RcloneFormat.HeaderSize +
            RcloneFormat.SaltSize +
            AesIvSize +
            ciphertext.Length +
            tag.Length
        ];

        var offset = 0;
        Buffer.BlockCopy(System.Text.Encoding.ASCII.GetBytes(RcloneFormat.HeaderMagic), 0, result, offset, 6);
        offset += 6;
        result[offset++] = 0;
        result[offset++] = 0;

        Buffer.BlockCopy(usedSalt, 0, result, offset, RcloneFormat.SaltSize);
        offset += RcloneFormat.SaltSize;

        Buffer.BlockCopy(nonce, 0, result, offset, AesIvSize);
        offset += AesIvSize;

        Buffer.BlockCopy(ciphertext, 0, result, offset, ciphertext.Length);
        offset += ciphertext.Length;

        Buffer.BlockCopy(tag, 0, result, offset, tag.Length);

        return result;
    }

    public byte[] Decrypt(byte[] data, string password)
    {
        if (data.Length < RcloneFormat.HeaderSize + RcloneFormat.SaltSize + AesIvSize + 16)
            throw new ArgumentException("Ciphertext too short");

        var header = System.Text.Encoding.ASCII.GetString(data, 0, 6);
        if (header != RcloneFormat.HeaderMagic)
            throw new ArgumentException("Invalid rclone format header");

        var offset = RcloneFormat.HeaderSize;

        var salt = new byte[RcloneFormat.SaltSize];
        Buffer.BlockCopy(data, offset, salt, 0, RcloneFormat.SaltSize);
        offset += RcloneFormat.SaltSize;

        var nonce = new byte[AesIvSize];
        Buffer.BlockCopy(data, offset, nonce, 0, AesIvSize);
        offset += AesIvSize;

        var ciphertextLength = data.Length - offset - 16;
        var ciphertext = new byte[ciphertextLength];
        Buffer.BlockCopy(data, offset, ciphertext, 0, ciphertextLength);
        offset += ciphertextLength;

        var tag = new byte[16];
        Buffer.BlockCopy(data, offset, tag, 0, 16);

        var (key, _) = _keyDerivation.DeriveKey(password, salt);

        using var aesGcm = new AesGcm(key, 16);
        var plaintext = new byte[ciphertext.Length];
        aesGcm.Decrypt(nonce, ciphertext, plaintext, tag);

        return plaintext;
    }

    public string EncryptFilename(string filename, string password, byte[]? salt = null, string encoding = "base32")
    {
        var (key, usedSalt) = _keyDerivation.DeriveKey(password, salt);
        var filenameBytes = System.Text.Encoding.UTF8.GetBytes(filename);

        using var aesGcm = new AesGcm(key, 16);
        var iv = new byte[AesIvSize];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(iv);
        }

        var encryptedData = new byte[filenameBytes.Length];
        var tag = new byte[16];
        aesGcm.Encrypt(iv, filenameBytes, encryptedData, tag);

        var result = new byte[
            RcloneFormat.HeaderSize +
            RcloneFormat.SaltSize +
            AesIvSize +
            encryptedData.Length +
            tag.Length
        ];

        var pos = 0;
        Buffer.BlockCopy(System.Text.Encoding.ASCII.GetBytes(RcloneFormat.HeaderMagic), 0, result, pos, 6);
        pos += 6;
        result[pos++] = 0;
        result[pos++] = 0;

        Buffer.BlockCopy(usedSalt, 0, result, pos, RcloneFormat.SaltSize);
        pos += RcloneFormat.SaltSize;

        Buffer.BlockCopy(iv, 0, result, pos, AesIvSize);
        pos += AesIvSize;

        Buffer.BlockCopy(encryptedData, 0, result, pos, encryptedData.Length);
        pos += encryptedData.Length;

        Buffer.BlockCopy(tag, 0, result, pos, tag.Length);

        return EncodeFilename(result, encoding);
    }

    public string DecryptFilename(string encodedFilename, string password, string encoding = "base32")
    {
        var data = DecodeFilename(encodedFilename, encoding);

        if (data.Length < RcloneFormat.HeaderSize + RcloneFormat.SaltSize + AesIvSize + 16)
            throw new ArgumentException("Ciphertext too short");

        var header = System.Text.Encoding.ASCII.GetString(data, 0, 6);
        if (header != RcloneFormat.HeaderMagic)
            throw new ArgumentException("Invalid rclone format header");

        var offset = RcloneFormat.HeaderSize;

        var salt = new byte[RcloneFormat.SaltSize];
        Buffer.BlockCopy(data, offset, salt, 0, RcloneFormat.SaltSize);
        offset += RcloneFormat.SaltSize;

        var iv = new byte[AesIvSize];
        Buffer.BlockCopy(data, offset, iv, 0, AesIvSize);
        offset += AesIvSize;

        var encryptedLength = data.Length - offset - 16;
        var encryptedData = new byte[encryptedLength];
        Buffer.BlockCopy(data, offset, encryptedData, 0, encryptedLength);
        offset += encryptedLength;

        var tag = new byte[16];
        Buffer.BlockCopy(data, offset, tag, 0, 16);

        var (key, _) = _keyDerivation.DeriveKey(password, salt);

        using var aesGcm = new AesGcm(key, 16);
        var plaintext = new byte[encryptedData.Length];
        aesGcm.Decrypt(iv, encryptedData, plaintext, tag);

        return System.Text.Encoding.UTF8.GetString(plaintext);
    }

    private static string EncodeFilename(byte[] data, string encoding)
    {
        return encoding.ToLowerInvariant() switch
        {
            "base32" => Base32Encode(data),
            "base64" => Convert.ToBase64String(data),
            "hex" => Convert.ToHexString(data),
            _ => throw new ArgumentException($"Unknown encoding: {encoding}")
        };
    }

    private static byte[] DecodeFilename(string encoded, string encoding)
    {
        return encoding.ToLowerInvariant() switch
        {
            "base32" => Base32Decode(encoded),
            "base64" => Convert.FromBase64String(encoded),
            "hex" => Convert.FromHexString(encoded),
            _ => throw new ArgumentException($"Unknown encoding: {encoding}")
        };
    }

    private static string Base32Encode(byte[] data)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var result = new System.Text.StringBuilder();
        int bitBuffer = 0;
        int bitCount = 0;

        foreach (byte b in data)
        {
            bitBuffer = (bitBuffer << 8) | b;
            bitCount += 8;

            while (bitCount >= 5)
            {
                bitCount -= 5;
                result.Append(alphabet[(bitBuffer >> bitCount) & 0x1F]);
            }
        }

        if (bitCount > 0)
        {
            result.Append(alphabet[(bitBuffer << (5 - bitCount)) & 0x1F]);
        }

        return result.ToString();
    }

    private static byte[] Base32Decode(string encoded)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        encoded = encoded.ToUpperInvariant().TrimEnd('=');

        var result = new List<byte>();
        int bitBuffer = 0;
        int bitCount = 0;

        foreach (char c in encoded)
        {
            int value = alphabet.IndexOf(c);
            if (value < 0)
                throw new ArgumentException($"Invalid base32 character: {c}");

            bitBuffer = (bitBuffer << 5) | value;
            bitCount += 5;

            if (bitCount >= 8)
            {
                bitCount -= 8;
                result.Add((byte)((bitBuffer >> bitCount) & 0xFF));
            }
        }

        return result.ToArray();
    }
}
