import bcrypt from 'bcryptjs';
// import jwt from 'express-jwt';
import jwt from 'jsonwebtoken';
import { OAuth2Client } from 'google-auth-library';
import crypto from 'crypto';
import dotenv from 'dotenv';
import { generateAccessToken, generateRefreshToken } from '../utils/utils.js';
import User from '../models/user.js';
import Token from '../models/token.js';
import Email from '../utils/email.js';

dotenv.config();

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

export const signin = async (req, res) => {
	const { email, password } = req.body;

	try {
		const oldUser = await User.findOne({ email });

		if (!oldUser)
			return res.status(404).json({ message: "User doesn't exist" });

		const isPasswordCorrect = await bcrypt.compare(password, oldUser.password);

		if (!isPasswordCorrect)
			return res.status(400).json({ message: 'Invalid credentials' });

		// if (!oldUser.verified) {
		// 	const token = await Token.findOne({ userId: oldUser._id });

		// 	if (!token) {
		// 		const newToken = new Token({
		// 			userId: oldUser._id,
		// 			token: crypto.randomBytes(16).toString('hex'),
		// 		}).save();

		// 		const url = `${process.env.FRONT_END_URL}/user/${oldUser._id}/confirmation/${newToken.token}`;
		// 		await new Email(oldUser, url).sendEmailVerification();

		// 		return res.status(200).json({
		// 			message:
		// 				'An email has been sent to you. Please verify your account to login.',
		// 		});
		// 	}

		// 	return res.status(400).json({ message: 'Please verify your email' });
		// }

		const accessToken = generateAccessToken({
			email: oldUser.email,
			name: oldUser.name,
			imageUrl: oldUser.imageUrl,
			_id: oldUser._id,
		});
		const refreshToken = generateRefreshToken({
			email: oldUser.email,
			_id: oldUser._id,
		});

		await User.findByIdAndUpdate(
			oldUser._id,
			{
				refreshToken: refreshToken,
			},
			{
				new: true,
			}
		);

		res.cookie('jwt', refreshToken, {
			httpOnly: true,
			secure: true,
			sameSite: 'None',
			maxAge: 7 * 24 * 60 * 60 * 1000,
		});

		res.cookie('access-token', accessToken, {
			httpOnly: false,
			secure: true,
			sameSite: 'None',
			maxAge: 15 * 60 * 1000,
		});

		res.status(200).json({
			user: {
				name: oldUser.name,
				email: oldUser.email,
				_id: oldUser._id,
				imageUrl: oldUser.imageUrl,
			},
			accessToken,
		});
	} catch (error) {
		res.status(500).json({ message: 'Something went wrong' });

		// console.log(error);
	}
};

export const signup = async (req, res) => {
	const { email, password, confirmPassword, firstName, lastName } = req.body;

	try {
		const oldUser = await User.findOne({ email });

		if (oldUser)
			return res.status(400).json({ message: 'User already exists' });

		if (password !== confirmPassword)
			return res.status(400).json({ message: "Passwords don't match" });

		const hashedPassword = await bcrypt.hash(password, 12);

		const result = await User.create({
			email,
			password: hashedPassword,
			name: `${firstName} ${lastName}`,
		});

		const token = await Token.create({
			userId: result._id,
			token: crypto.randomBytes(16).toString('hex'),
		});

		const url = `${process.env.FRONTEND_URL}/users/${result.id}/confirmation/${token.token}`;

		await new Email(result, url).sendWelcome();

		// res.status(200).json({
		// 	message: 'An email has been sent to you. Please verify your account',
		// });

		const accessToken = generateAccessToken({
			email: result.email,
			name: result.name,
			imageUrl: result.imageUrl,
			_id: result._id,
		});
		const refreshToken = generateRefreshToken({
			email: result.email,
			_id: result._id,
		});

		await User.findByIdAndUpdate(
			result._id,
			{
				refreshToken: refreshToken,
			},
			{
				new: true,
			}
		);

		res.cookie('jwt', refreshToken, {
			httpOnly: true,
			secure: true,
			sameSite: 'None',
			maxAge: 7 * 24 * 60 * 60 * 1000,
		});

		res.cookie('access-token', accessToken, {
			httpOnly: false,
			secure: true,
			sameSite: 'None',
			maxAge: 15 * 60 * 1000,
		});

		res.status(200).json({
			user: {
				name: result.name,
				email: result.email,
				_id: result._id,
				imageUrl: result.imageUrl,
			},
			accessToken,
		});
	} catch (error) {
		res.status(500).json({ message: 'Something went wrong' });

		// console.log(error);
	}
};

export const googleSignin = async (req, res) => {
	const { tokenId } = req.body;

	const response = await client.verifyIdToken({
		idToken: tokenId,
		audience: process.env.GOOGLE_CLIENT_ID,
	});

	const { email_verified, name, email, picture: imageUrl } = response.payload;

	if (email_verified) {
		const user = await User.findOne({ email });

		if (user) {
			const accessToken = generateAccessToken({
				email: user.email,
				name: user.name,
				imageUrl: user.imageUrl,
				_id: user._id,
			});
			const refreshToken = generateRefreshToken({
				email: user.email,
				_id: user._id,
			});

			res.cookie('jwt', refreshToken, {
				httpOnly: true,
				secure: true,
				sameSite: 'None',
				maxAge: 7 * 24 * 60 * 60 * 1000,
			});

			res.cookie('access-token', accessToken, {
				httpOnly: false,
				secure: true,
				sameSite: 'None',
				maxAge: 15 * 60 * 1000,
			});

			res.status(200).json({
				user: {
					name: user.name,
					email: user.email,
					_id: user._id,
					imageUrl: user.imageUrl,
				},
				accessToken,
			});
		} else {
			const password = email + process.env.GOOGLE_CLIENT_ID;
			const hashedPassword = await bcrypt.hash(password, 12);

			const result = await User.create({
				email,
				password: hashedPassword,
				name,
				imageUrl,
			});

			const accessToken = generateAccessToken({
				email: result.email,
				_id: result._id,
			});
			const refreshToken = generateRefreshToken({
				email: result.email,
				_id: result._id,
			});

			res.cookie('jwt', refreshToken, {
				httpOnly: true,
				secure: true,
				sameSite: 'None',
				maxAge: 7 * 24 * 60 * 60 * 1000,
			});

			res.cookie('access-token', accessToken, {
				httpOnly: false,
				secure: true,
				sameSite: 'None',
				maxAge: 15 * 60 * 1000,
			});

			res.status(200).json({
				user: {
					name: user.name,
					email: user.email,
					_id: user._id,
					imageUrl: user.imageUrl,
				},
				accessToken,
			});
		}
	}
};

export const signout = async (req, res) => {
	const cookies = req?.cookies;

	if (!cookies?.jwt) return res.status(204);

	const refreshToken = cookies.jwt;

	const foundUser = await User.findOne({ refreshToken });

	if (!foundUser) return res.status(204);

	await foundUser.updateOne({ refreshToken: '' });

	res.clearCookie('jwt', {
		httpOnly: true,
		secure: true,
		sameSite: 'None',
	});

	res.clearCookie('access-token', {
		httpOnly: false,
		secure: true,
		sameSite: 'None',
	});

	res.status(200).json({ message: 'Signout successfully' });
};

export const verifyEmail = async (req, res) => {
	const { id, token } = req.params;

	try {
		const user = await User.findById(id);
		if (!user) return res.status(404).json({ message: 'User not found' });

		const _token = await Token.findOne({ token });

		if (user.verified) {
			await _token.delete();
			return res.status(400).json({ message: 'Email already verified' });
		}

		if (!_token) return res.status(404).json({ message: 'Token not found' });

		if (_token.userId.toString() !== user.id.toString())
			return res.status(401).json({ message: 'Unauthorized' });

		await User.findByIdAndUpdate(user._id, { verified: true });

		await _token.delete();

		res.status(200).json({ message: 'Email verified successfully' });
	} catch (error) {
		res.status(500).json({ message: 'Something went wrong' });
	}
};

export const protect = async (req, res, next) => {
	try {
		if (
			!req.headers.authorization ||
			!req.headers.authorization.startsWith('Bearer')
		) {
			return res.status(401).json({ message: 'Unauthorized' });
		}

		const accessToken = req.headers.authorization.split(' ')[1];
		const refreshToken = req?.cookies?.jwt;
		const accessTokenCookie = req?.cookies?.['access-token'];

		const decodedUser = jwt.verify(
			accessToken,
			process.env.ACCESS_TOKEN_SECRET
		);

		const foundUser = await User.findById(decodedUser._id);

		if (!foundUser) return res.status(401).json({ message: 'Unauthorized' });

		if (foundUser.refreshToken !== refreshToken)
			return res.status(401).json({ message: 'Unauthorized' });

		if (accessTokenCookie !== accessToken)
			return res.status(401).json({ message: 'Unauthorized' });

		req.currentUser = decodedUser;

		next();
	} catch (err) {
		res.status(401).json({ message: 'jwt expired' });
	}
};

export const refresh = async (req, res) => {
	const cookies = req.cookies;
	if (!cookies?.jwt) return res.status(403).json({ message: 'Forbiden' });

	const refreshToken = cookies.jwt;

	jwt.verify(
		refreshToken,
		process.env.REFRESH_TOKEN_SECRET,
		async (err, decodedUser) => {
			if (err) return res.status(403).json({ message: 'Forbiden' });

			const foundUser = await User.findOne({ refreshToken });

			if (!foundUser) return res.status(403).json({ message: 'Forbiden' });

			if (foundUser.id !== decodedUser._id)
				return res.status(403).json({ message: 'Forbiden' });

			const newAccessToken = generateAccessToken({
				email: decodedUser.email,
				name: foundUser.name,
				imageUrl: foundUser.imageUrl,
				_id: decodedUser._id,
			});

			res.cookie('access-token', newAccessToken, {
				httpOnly: false,
				secure: true,
				sameSite: 'None',
				maxAge: 15 * 60 * 1000,
			});

			res.status(200).json({
				message: 'Refreshed',
				user: {
					name: foundUser.name,
					email: foundUser.email,
					imageUrl: foundUser.imageUrl,
					_id: foundUser.id,
				},
				accessToken: newAccessToken,
			});
		}
	);
};
