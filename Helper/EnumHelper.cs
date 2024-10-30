using Keynius.Backend.Contracts.Entity.Keywall;
using Olssen.Slp.CommandResults;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Keynius.Common.Helper
{
    public class EnumHelper
    {
        public static List<T> FindEnumsUsingSearchValue<T>(string searchString) where T : struct
        {
            searchString = searchString.Replace(" ", "").ToLower();
            var enumStringValues = new List<EnumStringWithEnumValueModel<T>>();
            var enumValuesList = Enum.GetValues(typeof(T)).Cast<T>().ToList();

            foreach (var item in enumValuesList)
                enumStringValues.Add(new EnumStringWithEnumValueModel<T> { EnumString = item.ToString(), EnumValue = item });

            return enumStringValues.Where(x => x.EnumString.ToLower().Contains(searchString)).Select(y => y.EnumValue).ToList();            
        }
    }
}
