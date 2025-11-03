const express = require("express");
const router = express.Router();

const {
  getAllPosts,
  getPost,
  createPost,
  updatePost,
  deletePost,
} = require("../controllers/postControllers");

const { protect } = require("../middleware/auth");

router.route('/').get(getAllPosts).post(protect, createPost);

router.route('/:id').get(getPost).put(protect, updatePost).delete(protect, deletePost);
module.exports = router;