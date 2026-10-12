var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();
app.MapGet("/healthz", () => "ok");
app.Run();
