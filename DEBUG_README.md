# Building

The SharpFuzz projects seem to build as usual. To build the sample fuzzing harness in 
`sharpfuzz/src/AngleSharp/AngleSharp.Fuzz`, I've been first running the SharpFuzz build then copying 
the assemblies from `sharpfuzz\src\SharpFuzz\bin\Debug\net48`
into `sharpfuzz\src\AngleSharp\AngleSharp.Fuzz` before running the build for the AngleSharp harness. 

# Debugging

The goal of this project is to implement another kind of SharpFuzz client. 
There is another Fuzzer class located in `sharpfuzz/src/SharpFuzz/Fuzzer.SfzFuzzer.cs`

I have constructed a testing fuzz harness in `sharpfuzz/src/AngleSharp/AngleSharp.Fuzz/Program.cs`

```
using System;
using AngleSharp.Parser.Html;
using System.Text;
using SharpFuzz;

namespace AngleSharp.Fuzz
{
	public class Program
	{
		public static void Main(string[] args)
		{
			Fuzzer.SfzFuzzer.RunSfz(args, (byte[] buffer) =>
			{
				try
				{
					var inputString = Encoding.UTF8.GetString(buffer);
					new HtmlParser().Parse(inputString);
				}
				catch (InvalidOperationException) { }
			});
		}
	}
}
```

SfzFuzzer is meant to receive signalling and data through two pipes and 4 shared memory regions. 

A test golang program which sets these up is located in `sharpfuzz/src/AngleSharp/AngleSharp.Fuzz/testee.go`

Once the golang executable is built, it can be invoked like so:
```
sharpfuzz\src\AngleSharp\AngleSharp.Fuzz> .\go_build_AngleSharp_Fuzz_.exe -exepath .\bin\Debug\net48\AngleSharp.Fuzz.exe
``` 

By placing a breakpoint at line 382 of testee.go, one can attach a debugger to the AngleSharp.Fuzz.exe
process:

```
	// Do the write
	if err = t.outFuzzPipe.WriteBuffer(t.writebuf[0:10]); err != nil {  // Line 382: Place breakpoint here
		log.Printf("write to testee failed: %v", err)
		retry = true
		return
	}
```

The corresponding breakpoint in the SfzFuzzer C# code is at line 91 of `Fuzzer.SfzFuzzer.cs`:

```
                            while (true)
                            {
                                int fnidx = 0;
                                long inputLength = 0;
                                (fnidx, inputLength) = ReadIndexAndLength(inStream);

                                // read inputBuffer data from comm0
                                var inputBuffer = new byte[inputLength];
```

When invoking `action(buffer)`, I consistently for the following error:

```
System.IO.FileLoadException: Could not load file or assembly 'SharpFuzz.Common, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null' or one of its dependencies. A strongly-named assembly is required. (Exception from HRESULT: 0x80131044)
File name: 'SharpFuzz.Common, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null'
   at AngleSharp.Parser.Html.HtmlParser..ctor()
   at AngleSharp.Fuzz.Program.<>c.<Main>b__0_0(Byte[] buffer) in C:\Users\PeterFuzz\sharpfuzz\src\AngleSharp\AngleSharp.Fuzz\Program.cs:line 17
   at SharpFuzz.Fuzzer.SfzFuzzer.RunSfz(String[] args, Action`1 action) in C:\Users\PeterFuzz\sharpfuzz\src\SharpFuzz\Fuzzer.SfzFuzzer.cs:line 136

```

I have tried changing the project properties of SharpFuzz.Common, to version 1.0.0.0, but this doesn't work.
