import uvicorn
from fastapi import FastAPI
from .core.config_manager import ConfigManager

app = FastAPI(title="DarkPen", version="1.0.0")
config = ConfigManager()

@app.get("/")
async def root():
    return {"status": "running", "version": "1.0.0"}

def main():
    """Run the application"""
    uvicorn.run(
        "darkpen.main:app",
        host=config.get("server.host", "0.0.0.0"),
        port=config.get("server.port", 8080),
        workers=config.get("server.workers", 4)
    )

if __name__ == "__main__":
    main() 