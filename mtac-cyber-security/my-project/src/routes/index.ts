import { Router } from 'express';
import IndexController from '../controllers';

const router = Router();
const indexController = new IndexController();

export function setRoutes(app) {
    app.use('/', router);
    router.get('/', indexController.handleHome);
    router.get('/about', indexController.handleAbout);
    // Add more routes as needed
}