namespace ApiCamScanner.Entities
{
    public class ChangePinRequest
    {
        public string Username { get; set; }
        public string CurrentPin { get; set; }
        public string NewPin { get; set; }
    }
}
