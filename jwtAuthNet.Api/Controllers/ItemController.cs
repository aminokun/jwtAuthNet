using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace jwtAuthNet.Api.Controllers
{
    [Authorize]
    [ApiController]
    public class ItemController : Controller
    {
        public List<string> colorList = new List<string>() { "blue", "red", "green", "yellow", "orange", "purple" };

        [HttpGet("GetColorList")]
        public List<string> GetColorList()
        {
            try
            {
                return colorList;
            }
            catch (Exception ex)
            {
                throw;
            }
        }

    }
}
