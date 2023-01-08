import { config } from 'dotenv';
config();

export default {
	origin: [...process.env.ALLOWED_ORIGINS.split(','), undefined],
	credentials: true,
	optionsSuccessStatus: 200,
};
