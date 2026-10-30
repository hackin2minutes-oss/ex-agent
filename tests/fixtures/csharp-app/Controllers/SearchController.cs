using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;

namespace Store.Controllers
{
    [ApiController]
    public class SearchController : ControllerBase
    {
        private readonly SqlCommand cmd = new SqlCommand();

        [HttpGet("search")]
        public IActionResult Search([FromQuery] string term)
        {
            var sql = "SELECT * FROM products WHERE name = '" + term + "'";
            cmd.CommandText = sql;
            cmd.ExecuteReader(sql); // SINK:tainted-local
            return Ok();
        }

        [HttpGet("direct")]
        public IActionResult Direct()
        {
            var q = Request.Query["q"];
            System.Diagnostics.Process.Start(q); // SINK:direct-request
            return Ok();
        }

        [HttpGet("constant")]
        public IActionResult Constant()
        {
            cmd.ExecuteReader("SELECT 1"); // SINK:constant
            return Ok();
        }

        [HttpGet("interpolated")]
        public IActionResult Interpolated([FromQuery] string id)
        {
            var text = $"SELECT * FROM orders WHERE id = {id}";
            cmd.ExecuteNonQuery(text); // SINK:interpolated
            return Ok();
        }

        [HttpPost("reassigned")]
        public IActionResult Reassigned([FromBody] string body)
        {
            var query = body;
            query = "SELECT 1";
            cmd.ExecuteNonQuery(query); // SINK:reassigned
            return Ok();
        }

        public string Build(string input)
        {
            return RunRaw(input); // SINK:unrouted
        }

        private string RunRaw(string value)
        {
            return value;
        }
    }
}
