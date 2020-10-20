using Microsoft.Win32.SafeHandles;
using System;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SharpFuzz
{
    /// <summary>
    /// SFZ Fuzzer instrumentation and fuzzer main loop for .NET libraries.
    /// </summary>
    public static partial class Fuzzer
    {
        /// <summary>
        /// SfzFuzzer class contains the SFZ fuzzer main loop implementation
        /// that can receive coordination through shared memory and pipes.
        /// </summary>
        public static class SfzFuzzer
        {
            /// <summary>
            /// Run method starts the .NET equivalent of SFZ fuzzer main loop.
            /// </summary>
            /// <param name="action">
            /// Some action that calls the instrumented library. The stream
            /// argument passed to the action contains the serialized input data. 
            /// </param>
            public static unsafe void RunSfz(string[] args, Action<byte[]> action)
            {
                Console.WriteLine("Starting Sfz Main");
                
                int[] fileDescriptors = ReadFileDescriptors(args);
                int fdIn = fileDescriptors[0];
                int fdOut = fileDescriptors[1];
                
                Console.Write("GO_FUZZ_IN_FD: " + fdIn);
                Console.WriteLine(" GO_FUZZ_OUT_FD: " + fdOut);

                string[] commName = ReadSharedMemoryNames(args);

                using (SafeFileHandle inPipeHandle = new SafeFileHandle(new IntPtr(fdIn), true),
                    outPipeHandle = new SafeFileHandle(new IntPtr(fdOut), true))
                {
                    // Use the filehandles
                    Stream inStream = new FileStream(inPipeHandle, FileAccess.Read);
                    Stream outStream = new FileStream(outPipeHandle, FileAccess.Write);
                    Console.WriteLine("created inStream and outStream");

                    //MemoryMappedFileSecurity security = new MemoryMappedFileSecurity();
                    //security.AddAccessRule(new AccessRule<MemoryMappedFileRights>(("Everyone"),
                    //    MemoryMappedFileRights.FullControl, AccessControlType.Allow));
                    //Console.WriteLine("created security");
                    
                    using (
                        MemoryMappedFile comm0 = MemoryMappedFile.OpenExisting(commName[0],
                            MemoryMappedFileRights.ReadWrite, HandleInheritability.Inheritable),
                        comm1 = MemoryMappedFile.OpenExisting(commName[1], MemoryMappedFileRights.ReadWrite,
                            HandleInheritability.Inheritable),
                        comm2 = MemoryMappedFile.OpenExisting(commName[2], MemoryMappedFileRights.ReadWrite,
                            HandleInheritability.Inheritable),
                        comm3 = MemoryMappedFile.OpenExisting(commName[3], MemoryMappedFileRights.ReadWrite,
                            HandleInheritability.Inheritable))
                    {
                        const int MaxInputSize = 1 << 24;
                        const int ReturnResultSize = 1 << 25;
                        const int CoverSize = 64 << 10;
                        const int SonarRegionSize = 1 << 20;

                        var cover = new byte[CoverSize];
                        fixed (byte* coverPtr = cover)
                        {
                            var trace = new TraceWrapper(coverPtr);

                            Console.WriteLine("created commX objects");

                            var comm0Accessor = comm0.CreateViewAccessor(0, MaxInputSize);
                            var comm1Accessor = comm1.CreateViewAccessor(0, ReturnResultSize);
                            var comm2Accessor = comm2.CreateViewAccessor(0, CoverSize);
                            var comm3Accessor = comm3.CreateViewAccessor(0, SonarRegionSize);
                            Console.WriteLine("created commX accessors");

                            while (true)
                            {
                                int fnidx = 0;
                                long inputLength = 0;
                                (fnidx, inputLength) = ReadIndexAndLength(inStream);

                                // read inputBuffer data from comm0
                                var inputBuffer = new byte[inputLength];
                                comm0Accessor.ReadArray(0, inputBuffer, 0, (int) inputLength);
                                for (int i = 0; i < inputLength; i++)
                                {
                                    inputBuffer[i] = comm0Accessor.ReadByte(i);
                                }

                                var inputString = Encoding.UTF8.GetString(inputBuffer);
                                Console.WriteLine("downstream: " + Encoding.UTF8.GetString(inputBuffer));
                                var downstream = new Downstream();
                                try
                                {
                                    downstream = JsonSerializer.Deserialize<Downstream>(inputString);
                                }
                                catch (Exception ex)
                                {
                                    Console.WriteLine("downstream deserialization exception: " + ex.Message);
                                }

                                //var downstream = FlatBufferSerializer.Default.Parse<Downstream>(inputBuffer);
                                Console.WriteLine("downstream deserialized");

                                Upstream upstream = NewUpstreamObj();

                                long res = 0;
                                long ns = 0;
                                long sonar = 0;

                                var seed = downstream.Seed;
                                if (seed != null && seed.Data != null && seed.Data.Length >= 1)
                                {
                                    ConfigEntry entry = seed.Data[0];
                                    var value = entry.Value;

                                    if (entry.Value != null)
                                    {
                                        Console.WriteLine("got entry value: " + value);

                                        // Start the clock
                                        var nsStart = DateTime.UtcNow.Ticks;

                                        try
                                        {
                                            // Actually run the function to fuzz
                                            byte[] buffer = Encoding.UTF8.GetBytes(value);
                                            action(buffer);
                                            Console.Write("exec fuzz method");
                                        }
                                        catch (Exception exception)
                                        {
                                            ns = DateTime.UtcNow.Ticks - nsStart;
                                            Console.WriteLine("ns: " + ns);

                                            upstream.Crashed = true;
                                            upstream.HasFailed = true;
                                            upstream.ResultMessage = exception.ToString();
                                        }
                                    }
                                    else
                                    {
                                        Console.WriteLine("null entry value!");
                                        var nsStart = DateTime.UtcNow.Ticks;
                                        try
                                        {
                                            // Actually run the function to fuzz
                                            byte[] buffer = Encoding.UTF8.GetBytes("<html><body><h1>h1</h1><p>p</p></body></html>");
                                            action(buffer);
                                            Console.Write("exec fuzz method");
                                        }
                                        catch (Exception exception)
                                        {
                                            ns = DateTime.UtcNow.Ticks - nsStart;
                                            Console.WriteLine("ns: " + ns);

                                            upstream.Crashed = true;
                                            upstream.HasFailed = true;
                                            upstream.ResultMessage = exception.ToString();
                                        }
                                    }
                                }
                                else
                                {
                                    Console.WriteLine("zero entries!");
                                    var nsStart = DateTime.UtcNow.Ticks;
                                    try
                                    {
                                        // Actually run the function to fuzz
                                        byte[] buffer = Encoding.UTF8.GetBytes("<html><body><h1>h1</h1><p>p</p></body></html>");
                                        action(buffer);
                                        Console.Write("exec fuzz method");
                                    }
                                    catch (Exception exception)
                                    {
                                        ns = DateTime.UtcNow.Ticks - nsStart;
                                        Console.WriteLine("ns: " + ns);

                                        upstream.Crashed = true;
                                        upstream.HasFailed = true;
                                        upstream.ResultMessage = exception.ToString();
                                    }
                                }

                                for (int i = 0; i < cover.Length; i++)
                                {
                                    if (cover[i] != 0)
                                    {
                                        Console.WriteLine("nonzero cover!");
                                    }
                                }
                                
                                // copy cover to shared memory
                                for (int i = 0; i < cover.Length; i++)
                                {
                                    comm2Accessor.Write(i, cover[i]);
                                }
                                comm2Accessor.Flush();
                                
                                ReturnResult(comm1Accessor, outStream, res, ns, sonar, upstream);

                            }
                        }
                    }
                }
            }
            
            public static int BrokenMethod(string Data)
            {
                int[] ints = new int[5]{0, 1, 2, 3, 4};
                int idx = 0;
                if (Data.Length > 5)
                {
                    idx++;
                }
                if (Data.Contains("foo"))
                {
                    idx++;
                }
                if (Data.Contains("bar"))
                {
                    idx++;
                }
                if (Data.Contains("ouch"))
                {
                    idx++;
                }
                if (Data.Contains("omg"))
                {
                    idx++;
                }
                return ints[idx];
            }

            public static int[] ReadFileDescriptors(string[] args)
            {
                int[] fileDescriptors = new int[6];
                for (int i = 0; i < fileDescriptors.Length; i++)
                {
                    int n = ParsedFd(args[i]);
                    Console.WriteLine(n);
                    fileDescriptors[i] = n;
                }

                return fileDescriptors;
            }

            public static string[] ReadSharedMemoryNames(string[] args)
            {
                string[] commName = new string[4];
                for (int i = 6; i < args.Length; i++)
                {
                    commName[i - 6] = args[i];
                }

                return commName;
            }
            public static int ParsedFd(string fdString)
            {
                int ptrd = 0;
                for (int i = 0; i < fdString.Length; i++) {
                    ptrd = ptrd * 10 + Int32.Parse(fdString[i].ToString());
                }

                return ptrd;
            }
            
            private static long Deserialize64(byte[] buf)
            {
                Int64 result = 0;
                result |= (long)buf[0];
                result |= (long)buf[1] << 8;
                result |= (long)buf[2] << 16;
                result |= (long)buf[3] << 24;
                result |= (long)buf[4] << 32;
                result |= (long)buf[5] << 40;
                result |= (long)buf[6] << 48;
                result |= (long)buf[7] << 56;
                return result;
            }
            private static long Serialize56(byte[] buf, Int64 v)
            {
                buf[0] = (byte) (v & 0xFF);
                buf[1] = (byte) ((v >> 8) & 0xFF);
                buf[2] = (byte) ((v >> 16) & 0xFF);
                buf[3] = (byte) ((v >> 24) & 0xFF);
                buf[4] = (byte) ((v >> 32) & 0xFF);
                buf[5] = (byte) ((v >> 40) & 0xFF);
                buf[6] = (byte) ((v >> 48) & 0xFF);
                buf[7] = buf[0];
                buf[7] ^= buf[1];
                buf[7] ^= buf[2];
                buf[7] ^= buf[3];
                buf[7] ^= buf[4];
                buf[7] ^= buf[5];
                buf[7] ^= buf[6];
                return buf[7];
            }
            
            private static (int, long) ReadIndexAndLength(Stream inPipeStream)
            {
                byte[] inPipeBuffer = new byte[10];
                inPipeStream.Read(inPipeBuffer, 0, 10);

                int fnidx = inPipeBuffer[0];
                fnidx += inPipeBuffer[1] << 8;

                byte[] lengthBuffer = new byte[8];
                for (int i = 2; i < inPipeBuffer.Length; i++)
                {
                    lengthBuffer[i-2] = inPipeBuffer[i];
                }
                long inputLength = Deserialize64(lengthBuffer);
            
                Console.Write("fnidx: " + fnidx);
                Console.WriteLine(" input length: " + inputLength);
            
                return (fnidx, inputLength);
            }
            
            private static void ReturnResult(MemoryMappedViewAccessor resultBufferAccessor, Stream outputStream, long res, long ns, long sonar, Upstream upstream)
            {
            byte[] resBuffer = new byte[8];
            byte[] nsBuffer = new byte[8];
            byte[] sonarBuffer = new byte[8];
            
            Serialize56(resBuffer, res);
            Serialize56(nsBuffer, ns);
            Serialize56(sonarBuffer, sonar);
            
            Console.WriteLine("serializing upstream");

            /*int maxReturnSize = FlatBufferSerializer.Default.GetMaxSize(upstream);
            var returnBuffer = new byte[maxReturnSize];
            returnLength = FlatBufferSerializer.Default.Serialize(upstream, returnBuffer);*/
            
            byte[] returnLengthBuffer = new byte[8];
            var returnResultBuffer = JsonSerializer.SerializeToUtf8Bytes<Upstream>(upstream);
            
            var jsonString = Encoding.UTF8.GetString(returnResultBuffer);
            Console.WriteLine("upstream json: " + jsonString);
            
            Serialize56(returnLengthBuffer, returnResultBuffer.Length);
            
            for (int i = 0; i < 8; i++)
            {
                resultBufferAccessor.Write(i, returnLengthBuffer[i]);
            }
            for (int i = 0; i < returnResultBuffer.Length; i++)
            {
                resultBufferAccessor.Write(i+8, returnResultBuffer[i]);
            }

            resultBufferAccessor.Flush();
            Console.WriteLine("wrote to comm1Accessor");
            
            byte[] outputBuffer = new byte[24];
            
            for (int i = 0; i < 8; i++)
            {
                outputBuffer[i] = resBuffer[i];
                outputBuffer[i+8] = nsBuffer[i];
                outputBuffer[i+16] = sonarBuffer[i];
            }
            
            outputStream.Write(outputBuffer, 0, outputBuffer.Length);
            outputStream.Flush();
            Console.WriteLine("wrote outputbuffer");
            }
            
            private static Upstream NewUpstreamObj()
            {
                Console.WriteLine("instantiating fake upstream");
                Upstream upstream = new Upstream();
                upstream.Structure = new FSeed();
                upstream.Structure.Data = new ConfigEntry[1];
                upstream.ResultMessage = "";
                ConfigEntry entry = new ConfigEntry();
                upstream.Structure.Data[0] = entry;
                entry.Tag = "stuff";
                entry.Type = "string";
                entry.Used = true;
                entry.Value = "<html><body><h1>h1</h1><p>p</p></body></html>";
                return upstream;
            }
            public class ConfigEntry
            {
                [JsonInclude,JsonPropertyName("tag")] public string Tag;
                [JsonInclude,JsonPropertyName("type")] public string Type;
                [JsonInclude,JsonPropertyName("used")] public bool Used;
                [JsonInclude,JsonPropertyName("v")] public string Value;
            }
            public class FSeed
            {
                [JsonInclude,JsonPropertyName("data")] public ConfigEntry[] Data;
            }
            public class Downstream
            {
                [JsonInclude,JsonPropertyName("seed")] public FSeed Seed;
            }

            public class Upstream
            {
                [JsonInclude,JsonPropertyName("crashed")] public bool Crashed;
                [JsonInclude,JsonPropertyName("failed")] public bool HasFailed;       
                [JsonInclude,JsonPropertyName("discard")] public bool MustDiscard;
                [JsonInclude,JsonPropertyName("save")] public bool MustSave;
                [JsonInclude,JsonPropertyName("skip")] public bool ShouldSkip;
                [JsonInclude,JsonPropertyName("structure")] public FSeed Structure;
                [JsonInclude,JsonPropertyName("message")] public string ResultMessage;
            }
        }
    }
}