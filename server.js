import express, { json, urlencoded } from 'express'
import connectToDB from './config/db.config.js'
import { configDotenv } from 'dotenv';
import appRouter from './routes/app.routes.js';
import cookieParser from 'cookie-parser';
configDotenv()

const app = express();

// common middlewares
app.use(json)
app.use(express.urlencoded({ extended: true }))
app.use(cookieParser())

// express routing
app.use('/api/v1', appRouter)

// testing the server
app.get('/ping', (_req, res) => {
    res.send('Pong');
});

const PORT = process.env.PORT

app.listen(PORT, () => {
    connectToDB();
    console.log(`Server is listening on port ${PORT}`);
});