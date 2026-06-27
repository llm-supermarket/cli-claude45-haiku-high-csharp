namespace Cli;

public class RcloneFormat
{
    public const string HeaderMagic = "RCLONE";
    public const int HeaderSize = 8;
    public const int NonceSize = 24;
    public const int KeySize = 32;
    public const int SaltSize = 16;
}
