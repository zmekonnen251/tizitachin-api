export const allowedOrigins = [
	'https://tizitachin-client.onrender.com',
];

export default {
	origin: function (origin, callback) {
		if (allowedOrigins.indexOf(origin) !== -1 || !origin) {
			callback(null, true);
		} else {
			
			callback(new Error('Not allowed by CORS'));
		}
	},
	optionSuccessStatus: 200,
	credentials: true,
};
