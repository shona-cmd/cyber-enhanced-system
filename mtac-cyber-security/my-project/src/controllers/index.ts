class IndexController {
    public async handleGetRequest(req: Request, res: Response): Promise<void> {
        // Handle GET request
        res.send("GET request handled");
    }

    public async handlePostRequest(req: Request, res: Response): Promise<void> {
        // Handle POST request
        res.send("POST request handled");
    }

    // Additional methods for other routes can be added here
}

export default IndexController;