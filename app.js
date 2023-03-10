import express from 'express';
import bodyParser from 'body-parser';
import dotenv from 'dotenv';
import cors from 'cors';
import morgan from 'morgan';
import cookieParser from 'cookie-parser';

import corsOptions from './config/corsOptions.js';

import postRoutes from './routes/posts.js';
import userRoutes from './routes/users.js';

dotenv.config();

const app = express();

if (process.env.NODE_ENV === 'development') {
	app.use(morgan('dev'));
}

app.use(cors(corsOptions));

app.use(express.static('react-client/build'));

app.use(express.json());

app.use(cookieParser());

app.use(express.urlencoded({ extended: false }));

app.use(bodyParser.json({ limit: '30mb', extended: true }));
app.use(bodyParser.urlencoded({ limit: '30mb', extended: true }));

app.use('/api/posts', postRoutes);
app.use('/api/users', userRoutes);

// app.get('/', (req, res) => {
// 	res.send('Hello to Memories API');
// });

app.get('/*', (req, res) => {
	res.sendFile('index.html', { root: 'react-client/build' });
});

export default app;
