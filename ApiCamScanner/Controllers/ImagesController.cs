using ApiCamScanner.Entities;
using Dapper;
using Microsoft.AspNetCore.Mvc;
using MySqlConnector;

namespace ApiCamScanner.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ImagesController : ControllerBase
    {
        private readonly IConfiguration _config;

        public ImagesController(IConfiguration config)
        {
            _config = config;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="groupId"></param>
        /// <returns></returns>


        [HttpGet("getAllImage/{groupId}")]
        public async Task<IActionResult> GetAllImages(int groupId)
        {
            try
            {
                // Kiểm tra sự tồn tại của GroupImage dựa trên GroupId
                bool groupImageExists = CheckGroupImageExists(groupId);
                if (!groupImageExists)
                {
                    return StatusCode(StatusCodes.Status404NotFound, "GroupImage not found");
                }

                // Lấy tất cả các Image trong GroupImage từ cơ sở dữ liệu
                List<Images> images = GetImagesByGroupId(groupId);
                
                    return StatusCode(StatusCodes.Status200OK, images);
                
               
            }
            catch (Exception exception)
            {
                Console.WriteLine(exception.Message);
                return StatusCode(StatusCodes.Status500InternalServerError, "An error occurred");
            }
        }

        private List<Images> GetImagesByGroupId(int groupId)
        {
            // Lấy tất cả các Image trong GroupImage từ cơ sở dữ liệu dựa trên GroupId
            // Ví dụ: Sử dụng ORM (Entity Framework, Dapper) để truy vấn dữ liệu từ MySQL

            //string connectionString = "Server=localhost;Port=3306;Database=camscanner;Uid=root;Pwd=12345678;";
            string connectionString = _config.GetConnectionString("MyConnection");

            MySqlConnection mySqlConnection = new MySqlConnection(connectionString);

            string selectImages = "SELECT * FROM images WHERE groupId = @groupId";

            var parameters = new DynamicParameters();
            parameters.Add("@groupId", groupId);

            List<Images> images = mySqlConnection.Query<Images>(selectImages, parameters).ToList();

            return images;
        }

        private bool CheckGroupImageExists(int groupId)
        {
            // Kiểm tra sự tồn tại của GroupImage dựa trên GroupId trong cơ sở dữ liệu
            // Ví dụ: Sử dụng ORM (Entity Framework, Dapper) để truy vấn dữ liệu từ MySQL

            string connectionString = "Server=localhost;Port=3306;Database=camscanner;Uid=root;Pwd=12345678;";
            MySqlConnection mySqlConnection = new MySqlConnection(connectionString);

            string selectGroupImage = "SELECT COUNT(*) FROM groupimages WHERE groupId = @groupId";

            var parameters = new DynamicParameters();
            parameters.Add("@groupId", groupId);

            int count = mySqlConnection.ExecuteScalar<int>(selectGroupImage, parameters);

            return count > 0;
        }


        /// <summary>
        ///     
        /// </summary>
        /// <param name="image"></param>
        /// <returns></returns>

        [HttpPost]
        [Route("InsertImage")]
        public async Task<IActionResult> InsertImage([FromBody] Images image)
        {
            try
            {
                // Establish a connection to the MySQL database
                //string connectionString = "Server=localhost;Port=3306;Database=camscanner;Uid=root;Pwd=12345678;";
                string connectionString = _config.GetConnectionString("MyConnection");

                var mySqlConnection = new MySqlConnection(connectionString);

                // Prepare the SQL query
                string insertImage = "INSERT INTO images (imageData, groupId) VALUES (@imageData, @groupId); SELECT LAST_INSERT_ID()";

                // Prepare the parameters for the query
                var parameters = new DynamicParameters();
                parameters.Add("@imageData", image.imageData);
                parameters.Add("@groupId", image.groupId);

                // Execute the query and retrieve the inserted image ID
                int imageId = mySqlConnection.ExecuteScalar<int>(insertImage, parameters);
                image.imageId = imageId;

                if (imageId != 0)
                {
                    return StatusCode(StatusCodes.Status200OK, image);
                }
                else
                {
                    return StatusCode(StatusCodes.Status400BadRequest, "e002");
                }
            }
            catch (Exception exception)
            {
                Console.WriteLine(exception.Message);
                return StatusCode(StatusCodes.Status400BadRequest, exception.Message);
            }
        }

        /// <summary>
        /// 
        /// 
        /// </summary>
        /// <param name="imageId"></param>
        /// <returns></returns>


       [HttpDelete("deleteImage/{imageId}")]
       public async Task<IActionResult> DeleteImage(int imageId)
        {
            try
            {
                // Kiểm tra sự tồn tại của Image dựa trên imageId
                bool imageExists = CheckImageExists(imageId);
                if (!imageExists)
                {
                    return StatusCode(StatusCodes.Status404NotFound, "Image not found");
                }

                // Thực hiện xóa Image từ cơ sở dữ liệu
                bool deleteImageSuccess = DeleteImageFromDatabase(imageId);
                if (deleteImageSuccess)
                {
                    return StatusCode(StatusCodes.Status200OK, "Image deleted successfully");
                }
                else
                {
                    return StatusCode(StatusCodes.Status500InternalServerError, "Failed to delete Image");
                }
            }
            catch (Exception exception)
            {
                Console.WriteLine(exception.Message);
                return StatusCode(StatusCodes.Status500InternalServerError, "An error occurred");
            }
        }

        private bool CheckImageExists(int imageId)
        {
            // Kiểm tra sự tồn tại của Image dựa trên imageId trong cơ sở dữ liệu
            // Ví dụ: Sử dụng ORM (Entity Framework, Dapper) để truy vấn dữ liệu từ MySQL

            //string connectionString = "Server=localhost;Port=3306;Database=camscanner;Uid=root;Pwd=12345678;";
            string connectionString = _config.GetConnectionString("MyConnection");

            MySqlConnection mySqlConnection = new MySqlConnection(connectionString);

            string selectImage = "SELECT COUNT(*) FROM images WHERE imageId = @imageId";

            var parameters = new DynamicParameters();
            parameters.Add("@imageId", imageId);

            int count = mySqlConnection.ExecuteScalar<int>(selectImage, parameters);

            return count > 0;
        }

        private bool DeleteImageFromDatabase(int imageId)
        {
            // Xóa Image từ cơ sở dữ liệu dựa trên imageId
            // Ví dụ: Sử dụng ORM (Entity Framework, Dapper) để thực hiện xóa trong MySQL

           // string connectionString = "Server=localhost;Port=3306;Database=camscanner;Uid=root;Pwd=12345678;";
            string connectionString = _config.GetConnectionString("MyConnection");

            MySqlConnection mySqlConnection = new MySqlConnection(connectionString);

            string deleteImage = "DELETE FROM images WHERE imageId = @imageId";

                var parameters = new DynamicParameters();
            parameters.Add("@imageId", imageId);

            int rowsAffected = mySqlConnection.Execute(deleteImage, parameters);

            return rowsAffected > 0;
        }

    }
}
