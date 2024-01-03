using ApiCamScanner.Entities;
using Dapper;
using Microsoft.AspNetCore.Mvc;
using MySqlConnector;

namespace ApiCamScanner.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class GroupImagesController : ControllerBase
    {
        private readonly IConfiguration _config;

        public GroupImagesController(IConfiguration config)
        {
            _config = config;
        }

        [HttpPost("InsertGroup")]
        public async Task<IActionResult> InsertGroup([FromBody] GroupImage groupImage)
        {
            try
            {
                string connectionString = _config.GetConnectionString("MyConnection");

                var mySqlConnection = new MySqlConnection(connectionString);

                string insertGroup = "INSERT INTO groupimages (groupName, groupDate, dataTypeId) VALUES (@groupName, @groupDate, @datatypeId); SELECT LAST_INSERT_ID()";

                    var parameters = new DynamicParameters();
                    parameters.Add("@groupName", groupImage.groupName);
                    parameters.Add("@groupDate", groupImage.groupDate);
                    parameters.Add("@dataTypeId", groupImage.dataTypeId);

                    // Execute the SQL query to insert the image and retrieve the last inserted ID
                    int groupId = mySqlConnection.ExecuteScalar<int>(insertGroup, parameters);

                    groupImage.groupId = groupId;

                    return StatusCode(StatusCodes.Status200OK, groupImage);
                
            }
            catch (Exception exception)
            {
                Console.WriteLine(exception.Message);
                return StatusCode(StatusCodes.Status400BadRequest, exception.Message);
            }
        }


        [HttpGet]
        [Route("getAllGroup/{dataTypeId}")]
        public async Task<IActionResult>  GetAllGroups(int dataTypeId)
        {
            try
            {   
                // Lấy tất cả các nhóm dựa trên userId
                List<GroupImage> groups = GetGroupsByDataTypeId(dataTypeId);

                return StatusCode(StatusCodes.Status200OK, groups);
            }
            catch (Exception exception)
            {
                Console.WriteLine(exception.Message);
                return StatusCode(StatusCodes.Status500InternalServerError, exception.Message);
            }
        }

        private List<GroupImage> GetGroupsByDataTypeId(int dataTypeId)
        {
            // Lấy tất cả các nhóm từ cơ sở dữ liệu dựa trên userId
            // Ví dụ: Sử dụng ORM (Entity Framework, Dapper) để truy vấn dữ liệu từ MySQL

            string connectionString = _config.GetConnectionString("MyConnection");

            MySqlConnection mySqlConnection = new MySqlConnection(connectionString);

            string selectGroups = "SELECT * FROM groupimages WHERE dataTypeId = @dataTypeId";

            var parameters = new DynamicParameters();
            parameters.Add("@dataTypeId", dataTypeId);

            List<GroupImage> groups = mySqlConnection.Query<GroupImage>(selectGroups, parameters).ToList();

            return groups;
        }


        /// <summary>
        /// Update
        /// </summary>
        /// <param name="group"></param>
        /// <returns></returns>
        [HttpPut("updateGroup")]
        public async Task<IActionResult> UpdateGroup([FromBody] GroupImage group)
        {
            try
            {
                // Kiểm tra trùng tên nhóm
                bool isDuplicate = CheckDuplicateGroupName(group.groupId, group.groupName);
                if (isDuplicate)
                {
                    return StatusCode(StatusCodes.Status400BadRequest, "Group name already exists");
                }

                // Thực hiện cập nhật tên nhóm trong cơ sở dữ liệu
                bool isSuccess = UpdateGroupName(group.groupId, group.groupName);
                if (isSuccess)
                {
                    return StatusCode(StatusCodes.Status200OK, "Group updated successfully");
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

        private bool CheckDuplicateGroupName(int groupId, string groupName)
        {
            // Kiểm tra trùng tên nhóm trong cơ sở dữ liệu, trừ nhóm hiện tại đang được sửa
            // Ví dụ: Sử dụng ORM (Entity Framework, Dapper) để truy vấn dữ liệu từ MySQL

            string connectionString = _config.GetConnectionString("MyConnection");

            MySqlConnection mySqlConnection = new MySqlConnection(connectionString);

            string selectGroup = "SELECT COUNT(*) FROM groupimages WHERE groupName = @groupName AND groupId != @groupId";

            var parameters = new DynamicParameters();
            parameters.Add("@groupName", groupName);
            parameters.Add("@groupId", groupId);

            int count = mySqlConnection.ExecuteScalar<int>(selectGroup, parameters);

            return count > 0;
        }

        private bool UpdateGroupName(int groupId, string groupName)
        {
            // Cập nhật tên nhóm trong cơ sở dữ liệu
            // Ví dụ: Sử dụng ORM (Entity Framework, Dapper) để thực hiện cập nhật trong MySQL

            string connectionString = _config.GetConnectionString("MyConnection");

            MySqlConnection mySqlConnection = new MySqlConnection(connectionString);

            string updateGroup = "UPDATE groupimages SET groupName = @groupName WHERE groupId = @groupId";

            var parameters = new DynamicParameters();
            parameters.Add("@groupName", groupName);
            parameters.Add("@groupId", groupId);

            int rowsAffected = mySqlConnection.Execute(updateGroup, parameters);

            return rowsAffected > 0;
        }



        /// <summary>
        /// 
        /// 
        /// </summary>
        /// <param name="groupId"></param>
        /// <returns></returns>

        [HttpDelete("deleteGroupImage/{groupId}")]
        public async Task<IActionResult> DeleteGroupImage(int groupId)
        {
            try
            {
                // Kiểm tra sự tồn tại của GroupImage dựa trên GroupId
                bool groupImageExists = CheckGroupImageExists(groupId);
                if (!groupImageExists)
                {
                    return StatusCode(StatusCodes.Status404NotFound, "GroupImage not found");
                }

                // Xóa tất cả các Image trong GroupImage trước
                DeleteAllImagesInGroup(groupId);


                // Thực hiện xóa GroupImage trong cơ sở dữ liệu
                bool deleteGroupImageSuccess = DeleteGroupImageFromDatabase(groupId);
                if (deleteGroupImageSuccess)
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


        private bool CheckGroupImageExists(int groupId)
        {
            // Kiểm tra sự tồn tại của GroupImage dựa trên GroupId trong cơ sở dữ liệu
            // Ví dụ: Sử dụng ORM (Entity Framework, Dapper) để truy vấn dữ liệu từ MySQL

            string connectionString = _config.GetConnectionString("MyConnection");

            MySqlConnection mySqlConnection = new MySqlConnection(connectionString);

            string selectGroupImage = "SELECT COUNT(*) FROM groupimages WHERE groupId = @groupId";

            var parameters = new DynamicParameters();
            parameters.Add("@groupId", groupId);

            int count = mySqlConnection.ExecuteScalar<int>(selectGroupImage, parameters);

            return count > 0;
        }

        private bool DeleteGroupImageFromDatabase(int groupId)
        {
            // Xóa GroupImage từ cơ sở dữ liệu dựa trên GroupId
            // Ví dụ: Sử dụng ORM (Entity Framework, Dapper) để thực hiện xóa trong MySQL

            string connectionString = _config.GetConnectionString("MyConnection");

            MySqlConnection mySqlConnection = new MySqlConnection(connectionString);

            string deleteGroupImage = "DELETE FROM groupimages WHERE groupId = @groupId";

            var parameters = new DynamicParameters();
            parameters.Add("@groupId", groupId);

            int rowsAffected = mySqlConnection.Execute(deleteGroupImage, parameters);

            return rowsAffected > 0;
        }
        private void DeleteAllImagesInGroup(int groupId)
        {
            // Xóa tất cả các Image trong GroupImage từ cơ sở dữ liệu dựa trên GroupId
            // Ví dụ: Sử dụng ORM (Entity Framework, Dapper) để thực hiện xóa trong MySQL

            string connectionString = _config.GetConnectionString("MyConnection");

            MySqlConnection mySqlConnection = new MySqlConnection(connectionString);

            string deleteImages = "DELETE FROM images WHERE groupId = @groupId";

            var parameters = new DynamicParameters();
            parameters.Add("@groupId", groupId);

            int rowsAffected = mySqlConnection.Execute(deleteImages, parameters);

        }


    }



}
