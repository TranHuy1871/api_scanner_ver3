using ApiCamScanner.Entities;
using Dapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MySqlConnector;

namespace ApiCamScanner.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class DocumentsController : ControllerBase
    {
        private readonly IConfiguration _config;

        public DocumentsController(IConfiguration config)
        {
            _config = config;
        }
        [HttpPost("InsertDocument")]  // Sửa tên hàm thành "InsertDocument"
        public async Task<IActionResult> InsertDocument([FromBody] Documents document)
        {
            try
            {
                // Lấy connection string từ cấu hình
                string connectionString = _config.GetConnectionString("MyConnection");

                using (var mySqlConnection = new MySqlConnection(connectionString))
                {
                    // Mở kết nối
                    mySqlConnection.Open();

                    // Tạo câu lệnh SQL với tham số được thay thế
                    string insertDocument = "INSERT INTO documents (documentName, userId, date) VALUES (@documentName, @userId, @date); SELECT LAST_INSERT_ID()";

                    // Tạo đối tượng DynamicParameters và thêm tham số
                    var parameters = new DynamicParameters();
                    parameters.Add("@documentName", document.documentName);
                    parameters.Add("@userId", document.userId);
                    parameters.Add("@date", document.date);

                    // Thực thi câu lệnh SQL và lấy kết quả
                    int documentId = await mySqlConnection.ExecuteScalarAsync<int>(insertDocument, parameters);

                    // Cập nhật documentId cho đối tượng document
                    document.documentId = documentId;

                    // Trả về kết quả 200 OK với đối tượng document đã cập nhật
                    return StatusCode(StatusCodes.Status200OK, document);
                }
            }
            catch (Exception exception)
            {
                Console.WriteLine(exception.Message);
                return StatusCode(StatusCodes.Status500InternalServerError, "Internal server error");
            }
        }


        [HttpGet]
        [Route("GetAllDocument/{userId}")]
        [Authorize]
        public async Task<IActionResult> GetAllDocument(int userId)
        {
            try
            {
                // Lấy tất cả các nhóm dựa trên userId
                List<Documents> groups = GetAllDocumentByUserId(userId);

                return StatusCode(StatusCodes.Status200OK, groups);
            }
            catch (Exception exception)
            {
                Console.WriteLine(exception.Message);
                return StatusCode(StatusCodes.Status500InternalServerError, exception.Message);
            }
        }

        private List<Documents> GetAllDocumentByUserId(int userId)
        {
            // Lấy tất cả các nhóm từ cơ sở dữ liệu dựa trên userId
            // Ví dụ: Sử dụng ORM (Entity Framework, Dapper) để truy vấn dữ liệu từ MySQL

            string connectionString = _config.GetConnectionString("MyConnection");

            MySqlConnection mySqlConnection = new MySqlConnection(connectionString);

            string selectDocument = "SELECT * FROM documents WHERE userId = @userId";

            var parameters = new DynamicParameters();
            parameters.Add("@userId", userId);

            List<Documents> groups = mySqlConnection.Query<Documents>(selectDocument, parameters).ToList();

            return groups;
        }


        /// <summary>
        /// Update
        /// </summary>
        /// <param name="group"></param>
        /// <returns></returns>
        [HttpPut("updateDocument")]
        public async Task<IActionResult> UpdateDocument([FromBody] Documents document)
        {
            try
            {
                // Kiểm tra trùng tên nhóm
                bool isDuplicate = CheckDuplicateDocumentName(document.documentId, document.documentName);
                if (isDuplicate)
                {
                    return StatusCode(StatusCodes.Status400BadRequest, "Group name already exists");
                }

                // Thực hiện cập nhật tên nhóm trong cơ sở dữ liệu
                bool isSuccess = UpdateDocumentName(document.documentId, document.documentName);
                if (isSuccess)
                {
                    return StatusCode(StatusCodes.Status200OK, "Document updated successfully");
                }
                else
                {
                    return StatusCode(StatusCodes.Status500InternalServerError, "Failed to update group");
                }
            }
            catch (Exception exception)
            {
                Console.WriteLine(exception.Message);
                return StatusCode(StatusCodes.Status500InternalServerError, "An error occurred");
            }
        }

        private bool CheckDuplicateDocumentName(int documentId, string documentName)
        {
            // Kiểm tra trùng tên nhóm trong cơ sở dữ liệu, trừ nhóm hiện tại đang được sửa
            // Ví dụ: Sử dụng ORM (Entity Framework, Dapper) để truy vấn dữ liệu từ MySQL

            string connectionString = _config.GetConnectionString("MyConnection");

            MySqlConnection mySqlConnection = new MySqlConnection(connectionString);

            string selectGroup = "SELECT COUNT(*) FROM documents WHERE documentName = @documentName AND documentId != @documentId";

            var parameters = new DynamicParameters();
            parameters.Add("@documentName", documentName);
            parameters.Add("@documentId", documentId);

            int count = mySqlConnection.ExecuteScalar<int>(selectGroup, parameters);

            return count > 0;
        }

        private bool UpdateDocumentName(int documentId, string documentName)
        {
       

            string connectionString = _config.GetConnectionString("MyConnection");

            MySqlConnection mySqlConnection = new MySqlConnection(connectionString);

            string updateGroup = "UPDATE documents SET documentName = @documentName WHERE documentId = @documentId";

            var parameters = new DynamicParameters();
            parameters.Add("@documentName", documentName);
            parameters.Add("@documentId", documentId);

            int rowsAffected = mySqlConnection.Execute(updateGroup, parameters);

            return rowsAffected > 0;
        }



        /// <summary>
        /// 
        /// 
        /// </summary>
        /// <param name="groupId"></param>
        /// <returns></returns>

        [HttpDelete("deleteDocument/{documentId}")]
        public async Task<IActionResult> DeleteDocument(int documentId)
        {
            try
            {
                // Kiểm tra sự tồn tại của GroupImage dựa trên GroupId
                bool DocumentExists = CheckDocumentExists(documentId);
                if (!DocumentExists)
                {
                    return StatusCode(StatusCodes.Status404NotFound, "GroupImage not found");
                }
                // Thực hiện xóa GroupImage trong cơ sở dữ liệu
                bool deleteDocumentSuccess = DeleteDocumentFromDatabase(documentId);
                if (deleteDocumentSuccess)
                {
                    return StatusCode(StatusCodes.Status200OK, "GroupImage deleted successfully");
                }
                else
                {
                    return StatusCode(StatusCodes.Status500InternalServerError, "Failed to delete GroupImage");
                }
            }
            catch (Exception exception)
            {
                Console.WriteLine(exception.Message);
                return StatusCode(StatusCodes.Status500InternalServerError, "An error occurred");
            }
        }


        private bool CheckDocumentExists(int documentId)
        {
            // Kiểm tra sự tồn tại của GroupImage dựa trên GroupId trong cơ sở dữ liệu
            // Ví dụ: Sử dụng ORM (Entity Framework, Dapper) để truy vấn dữ liệu từ MySQL

            string connectionString = _config.GetConnectionString("MyConnection");

            MySqlConnection mySqlConnection = new MySqlConnection(connectionString);

            string selectGroupImage = "SELECT COUNT(*) FROM documents WHERE documentId = @documentId";

            var parameters = new DynamicParameters();
            parameters.Add("@documentId", documentId);

            int count = mySqlConnection.ExecuteScalar<int>(selectGroupImage, parameters);

            return count > 0;
        }

        private bool DeleteDocumentFromDatabase(int documentId)
        {
            // Xóa GroupImage từ cơ sở dữ liệu dựa trên GroupId
            // Ví dụ: Sử dụng ORM (Entity Framework, Dapper) để thực hiện xóa trong MySQL

            string connectionString = _config.GetConnectionString("MyConnection");

            MySqlConnection mySqlConnection = new MySqlConnection(connectionString);

            string deleteGroupImage = "DELETE FROM documents WHERE documentId = @documentId";

            var parameters = new DynamicParameters();
            parameters.Add("@documentId", documentId);

            int rowsAffected = mySqlConnection.Execute(deleteGroupImage, parameters);

            return rowsAffected > 0;
        }

    }



}
