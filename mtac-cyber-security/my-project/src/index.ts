import express from 'express';
import { setRoutes } from './routes';
import { IndexController } from './controllers';

const app = express();
const port = process.env.PORT || 3000;

// Middleware setup
app.use(express.json());

// Initialize routes
setRoutes(app);

// Start the server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});