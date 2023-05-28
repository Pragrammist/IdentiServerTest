using System.Data;
using Microsoft.AspNetCore.Mvc;
using Dapper;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace WebClient.Pages;

public class IndexModel : PageModel
{
    private readonly ILogger<IndexModel> _logger;
    private readonly IDbConnection _db;
    public IndexModel(ILogger<IndexModel> logger, IDbConnection db)
    {
        _logger = logger;
        _db = db;
    }
    [BindProperty]
    public WriteCommentModel WriteCommentModel { get; set; } = null!;
    public IEnumerable<CommentViewModel> Comments { get; set; } = new List<CommentViewModel>();

    [BindProperty]
    public string ReturnUrl { get; set; } = null!;

    public async Task OnGet(string returnUrl)
    {
        ReturnUrl = Request.Path;
        Comments = await _db.QueryAsync<CommentViewModel>(@"SELECT comments.Id, [Text], UserId, [Login] FROM comments INNER JOIN users ON comments.UserId = users.Id ORDER BY comments.Id DESC");
        
    }
    public async Task<IActionResult> OnPost()
    {
        if(WriteCommentModel is null)
            return Content("model is null");

        await _db.ExecuteAsync(@"INSERT comments (Text, UserId) VALUES(@Text, @UserId)", new {
            Text = WriteCommentModel.Text,
            UserId = int.Parse(User.Claims.First(f => f.Type == "sub").Value)
        });

        return Redirect(ReturnUrl);
    }
}

public record WriteCommentModel(string Text);

public class CommentViewModel
{
    public string Text { get; set; } = null!;

    public string Login { get; set; } = null!;

}