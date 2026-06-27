using Cli;

if (args.Length < 2)
{
    PrintUsage();
    Environment.Exit(1);
}

var command = args[0];
var parsedArgs = ParseArguments(args.Skip(1).ToArray());

try
{
    if (command == "encrypt")
    {
        HandleEncrypt(parsedArgs);
    }
    else if (command == "decrypt")
    {
        HandleDecrypt(parsedArgs);
    }
    else
    {
        Console.Error.WriteLine($"Unknown command: {command}");
        PrintUsage();
        Environment.Exit(1);
    }
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Error: {ex.Message}");
    Environment.Exit(1);
}

return 0;

static void PrintUsage()
{
    Console.WriteLine("Usage: cli-claude45-haiku-csharp <command> [options]");
    Console.WriteLine();
    Console.WriteLine("Commands:");
    Console.WriteLine("  encrypt  Encrypt a file");
    Console.WriteLine("  decrypt  Decrypt a file");
    Console.WriteLine();
    Console.WriteLine("Options:");
    Console.WriteLine("  -i, --input-file <path>    Input file (required)");
    Console.WriteLine("  -o, --output-file <path>   Output file (optional)");
    Console.WriteLine("  -p, --password <pwd>       Password (WARNING: visible in process, use env var)");
    Console.WriteLine("  -s, --salt <hex>           Salt in hex format (optional)");
    Console.WriteLine("  -e, --encoding <type>      Encoding: base32, base64, hex (default: base32)");
}

static Dictionary<string, string> ParseArguments(string[] args)
{
    var result = new Dictionary<string, string>();
    for (int i = 0; i < args.Length; i++)
    {
        var arg = args[i];
        if ((arg == "-i" || arg == "--input-file") && i + 1 < args.Length)
        {
            result["input"] = args[++i];
        }
        else if ((arg == "-o" || arg == "--output-file") && i + 1 < args.Length)
        {
            result["output"] = args[++i];
        }
        else if ((arg == "-p" || arg == "--password") && i + 1 < args.Length)
        {
            result["password"] = args[++i];
        }
        else if ((arg == "-s" || arg == "--salt") && i + 1 < args.Length)
        {
            result["salt"] = args[++i];
        }
        else if ((arg == "-e" || arg == "--encoding") && i + 1 < args.Length)
        {
            result["encoding"] = args[++i];
        }
    }
    return result;
}

static void HandleEncrypt(Dictionary<string, string> args)
{
    if (!args.ContainsKey("input"))
    {
        throw new ArgumentException("Input file not specified (-i or --input-file)");
    }

    var inputPath = args["input"];
    if (!File.Exists(inputPath))
    {
        throw new FileNotFoundException($"Input file not found: {inputPath}");
    }

    var outputPath = args.ContainsKey("output") ? args["output"] : inputPath + ".encrypted";

    var password = args.ContainsKey("password") ? args["password"] : GetPassword("Enter password: ");

    if (args.ContainsKey("password"))
    {
        Console.Error.WriteLine("Warning: Using --password in command line is insecure. Consider using RCLONE_PASSWORD env var instead.");
        Console.Error.WriteLine("Also remember to clear your shell history: history -c");
    }

    byte[]? saltBytes = null;
    if (args.ContainsKey("salt"))
    {
        try
        {
            saltBytes = Convert.FromHexString(args["salt"]);
        }
        catch
        {
            throw new ArgumentException("Invalid salt format (expected hex)");
        }
    }

    var fileBytes = File.ReadAllBytes(inputPath);
    var encryptionService = new RcloneEncryptionService();
    var encryptedBytes = encryptionService.Encrypt(fileBytes, password, saltBytes);
    File.WriteAllBytes(outputPath, encryptedBytes);
    Console.WriteLine($"Encrypted to: {outputPath}");
}

static void HandleDecrypt(Dictionary<string, string> args)
{
    if (!args.ContainsKey("input"))
    {
        throw new ArgumentException("Input file not specified (-i or --input-file)");
    }

    var inputPath = args["input"];
    if (!File.Exists(inputPath))
    {
        throw new FileNotFoundException($"Input file not found: {inputPath}");
    }

    var outputPath = args.ContainsKey("output") ? args["output"] : inputPath + ".decrypted";

    var password = args.ContainsKey("password") ? args["password"] : GetPassword("Enter password: ");

    if (args.ContainsKey("password"))
    {
        Console.Error.WriteLine("Warning: Using --password in command line is insecure. Consider using RCLONE_PASSWORD env var instead.");
        Console.Error.WriteLine("Also remember to clear your shell history: history -c");
    }

    var fileBytes = File.ReadAllBytes(inputPath);
    var encryptionService = new RcloneEncryptionService();
    var decryptedBytes = encryptionService.Decrypt(fileBytes, password);
    File.WriteAllBytes(outputPath, decryptedBytes);
    Console.WriteLine($"Decrypted to: {outputPath}");
}

static string GetPassword(string prompt)
{
    Console.Write(prompt);
    var password = string.Empty;
    ConsoleKey key;
    do
    {
        var keyInfo = Console.ReadKey(intercept: true);
        key = keyInfo.Key;

        if (key == ConsoleKey.Backspace)
        {
            if (password.Length > 0)
            {
                password = password[0..^1];
                Console.Write("\b \b");
            }
        }
        else if (key != ConsoleKey.Enter)
        {
            password += keyInfo.KeyChar;
            Console.Write("*");
        }
    } while (key != ConsoleKey.Enter);

    Console.WriteLine();
    return password;
}
