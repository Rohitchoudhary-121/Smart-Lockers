using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;

namespace Keynius.Common.Helper
{
    public class JsonHelper
    {
        public static TModel ReadJsonFile<TModel>(TModel model, string pathString)
        {
            string json = string.Empty;
            var path = Directory.GetCurrentDirectory() + pathString;

            Console.WriteLine("customerEmailConfigurations JsonFIlePath " + path);
            using (StreamReader r = new StreamReader(path))
            {
                json = r.ReadToEnd();
            }
            if (string.IsNullOrEmpty(json))
                throw new Exception();

            Console.WriteLine("Read Json " + json);
            return JsonSerializer.Deserialize<TModel>(json);
        }
    }
}
