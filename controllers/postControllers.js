const Post=require('../models/post');

// Create a new post
exports.createPost=async(req,res)=>{
    try{
        const {title,content,tags}=req.body;
        const author=req.user._id; // assuming user info is in req.user
        const newPost=await Post.create({title,content,author,tags});
        res.status(201).json({success:true,data:newPost});
    }
    catch(error){
        res.status(500).json({success:false,message:error.message});
    }
}

// Get a single post by ID
exports.getPost= async(req,res)=>{
    try{
        const post=await Post.findById(req.params.id).populate('author','name email').populate('comments.user','name');
        if(!post){
            return res.status(404).json({success:false,message:'Post not found'});
        }
        res.status(200).json({success:true,data:post});

    }
    catch(error){
        res.status(500).json({success:false,message:error.message});
    }}

// Update a post
exports.updatePost = async(req,res)=>{
    try{
        let post=await Post.findById(req.params.id);
        if(!post){
            return res.status(404).json({success:false,message:'Post not found'});
        }
        // Check if the logged-in user is the author
        if(post.author.toString()!==req.user._id.toString()){
            return res.status(403).json({success:false,message:'Unauthorized'});
        }
        post=await Post.findByIdAndUpdate(req.params.id,req.body,{new:true,runValidators:true});
        res.status(200).json({success:true,data:post});
    }
    catch(error){
        res.status(500).json({success:false,message:error.message});
    }
}

//delete a post
exports.deletePost=async(req,res)=>{
    try{
        const post=await Post.findById(req.params.id);
        if(!post){
            return res.status(404).json({success:false,message:'Post not found'});
        }
        // Check if the logged-in user is the author
        if(post.author.toString()!==req.user._id.toString()){
            return res.status(403).json({success:false,message:'Unauthorized'});
        }
        await post.deleteOne();
        res.status(200).json({success:true,message:'Post deleted successfully'});
    }
    catch(error){
        res.status(500).json({success:false,message:error.message});
    }}

// Get all posts with pagination and filtering
exports.getAllPosts=async(req,res)=>{
    try{
        
    const page = parseInt(req.query.page, 10) || 1;
    const limit = parseInt(req.query.limit, 10) || 10;
    const startIndex = (page - 1) * limit;
    const queryObj = {... req.query};
    
const field=["page","limit","sort"];
field.forEach(el=>delete queryObj[el]);

    let query  = Post.find(queryObj).populate('author','name email').skip(startIndex).limit(limit);
        const sortBy=req.query.sort;
        if(sortBy){
            const sortCriteria=sortBy.split(',').join(' ');
            query=query.sort(sortCriteria);
        }else {
            query=query.sort('-createdAt');
        }

        const posts=await query;
        const total=await Post.countDocuments(queryObj);

        res.status(200).json({
            success:true,
            count:posts.length,
            total,
            page,
            pages:Math.ceil(total/limit),
            data:posts
        });

    }
    catch(error){
        res.status(500).json({success:false,message:error.message});
    }
}