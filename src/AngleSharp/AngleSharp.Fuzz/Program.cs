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
