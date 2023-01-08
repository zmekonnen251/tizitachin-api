import mongoose from 'mongoose';
import PostMessage from '../models/postMessage.js';

export const getPost = async (req, res) => {
	const { id } = req.params;

	try {
		const post = await PostMessage.findById(id);

		res.status(200).json(post);
	} catch (error) {
		res.status(404).json({ message: error.message });
	}
};

export const getPosts = async (req, res) => {
	const { page } = req.query;
	try {
		const LIMIT = 9;
		const startIndex = (Number(page) - 1) * LIMIT; // get the starting index of every page
		const total = await PostMessage.countDocuments({});
		const posts = await PostMessage.find()
			.sort({ _id: -1 })
			.limit(LIMIT)
			.skip(startIndex);

		res.status(200).json({
			data: posts,
			currentPage: Number(page),
			numberOfPages: Math.ceil(total / LIMIT),
		});
	} catch (error) {
		res.status(404).json({ message: error.message });
	}
};

export const getPostsBySearch = async (req, res) => {
	const { searchQuery, tags } = req.query;
	console.log('searchQuery', searchQuery);
	console.log('tags', tags);
	try {
		const title = new RegExp(searchQuery, 'i');
		if (tags === '') {
			const posts = await PostMessage.find({ title });
			return res.status(200).json({ data: posts });
		}

		const posts = await PostMessage.find({
			$or: [{ title }, { tags: { $in: tags.split(',') } }],
		});

		res.status(200).json({ data: posts });
	} catch (error) {
		console.log(error);
		res.status(404).json({ message: error.message });
	}
};

export const createPost = async (req, res) => {
	const post = req.body;

	const newPost = new PostMessage({
		...post,
		creator: req.currentUser._id,
		createdAt: new Date().toISOString(),
	});

	try {
		await newPost.save();

		res.status(200).json(newPost);
	} catch (error) {
		res.status(409).json({ message: error.message });
	}
};

export const updatePost = async (req, res) => {
	const { id } = req.params;
	const post = req.body;

	if (!mongoose.Types.ObjectId.isValid(id))
		return res.status(404).send('No post with that id');

	if (post.creator !== req.currentUser._id)
		return res.status(403).send('You are not allowed to update this post');

	const updatedPost = await PostMessage.findByIdAndUpdate(id, post, {
		new: true,
	});

	res.status(200).json(updatedPost);
};

export const deletePost = async (req, res) => {
	const { id } = req.params;

	if (!mongoose.Types.ObjectId.isValid(id))
		return res.status(404).send('No post with that id');

	const post = await PostMessage.findById(id);

	if (post.creator !== req.currentUser._id)
		return res.status(403).send('You are not allowed to delete this post');

	await PostMessage.findByIdAndRemove(id);

	res.json({ message: 'Post deleted successfully' });
};

export const likePost = async (req, res) => {
	const { id } = req.params;

	if (!req.currentUser) return res.json({ message: 'Unauthenticated' });

	if (!mongoose.Types.ObjectId.isValid(id))
		return res.status(404).send('No post with that id');

	const post = await PostMessage.findById(id);

	const index = post.likes.findIndex(
		(id) => id === String(req.currentUser._id)
	);

	if (index === -1) {
		// like the post
		post.likes.push(req.currentUser._id);
	} else {
		// dislike a post
		post.likes = post.likes.filter((id) => id !== String(req.currentUser._id));
	}

	const updatedPost = await PostMessage.findByIdAndUpdate(id, post, {
		new: true,
	});

	res.status(200).json(updatedPost);
};

export const commentPost = async (req, res) => {
	const { id } = req.params;
	const { value } = req.body;

	const post = await PostMessage.findById(id);

	post.comments.push(value);

	const updatedPost = await PostMessage.findByIdAndUpdate(id, post, {
		new: true,
	});

	res.status(200).json(updatedPost);
};
