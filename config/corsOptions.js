export const allowedOrigins = [
	'https://tizitachin-client.onrender.com',
	'https://lighthearted-conkies-ef6707.netlify.app'
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
