import allowedOrigins from './allowedOrigins.js';

export default {
	// origin: (origin, callback) => {
	// 	if (allowedOrigins.indexOf(origin) !== -1) {
	// 		callback(null, true);
	// 	} else {
	// 		callback(new Error('Not allowed by CORS'));
	// 	}
	// },
	origin: [
		'http://localhost:3000',
		'https://tizitachin-client.onrender.com',
		'https://tizitachin.netlify.app',
		undefined,
	],
	credentials: true,
	optionsSuccessStatus: 200,
};
