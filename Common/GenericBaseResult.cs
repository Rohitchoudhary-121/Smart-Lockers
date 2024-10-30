namespace WebApplication1.Common
{
    public class GenericBaseResult<TModel> : BaseResult
    {
        public GenericBaseResult(TModel model)
        {
            Result = model;
        }

        public TModel Result { get; set; }
    }
}
