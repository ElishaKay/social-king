const edjsHTML = require('editorjs-html');
const edjsParser = edjsHTML();

const Blog = require('../../models/blog');
const Comment = require('../../models/comment');
const Emoji = require('../../models/emoji');

const Tag = require('../../models/tag');
const User = require('../../models/user');
const Shop = require('../../models/Shop');

const slugify = require('slugify');
const stripHtml = require('string-strip-html');
const _ = require('lodash');
const { errorHandler } = require('../helpers/dbErrorHandler');
const fs = require('fs');
const { smartTrim, makeid } = require('../helpers/blog');

const sgMail = require('@sendgrid/mail'); // SENDGRID_API_KEY
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// liquid-templates functions
const { blogsList } = require('../liquid-templates/blogsList');
const { blogSlug } = require('../liquid-templates/blogSlug');
const { notFound } = require('../liquid-templates/components/not-found/notFound');
const {translations} = require('../helpers/translations')

exports.create = (req, res) => {
    res.setHeader('content-type', 'text/javascript')
    let { title, body, tags } = req.body;
    console.log('req.body in createPost function',req.body);
    
    if (body.blocks === undefined || body.blocks.length == 0) {
        return res.status(400).json({
            error: 'Content is required'
        });
    }

    let blog = new Blog();
    blog.shopifyDomain=req.query.shop;
    blog.body = body;
    let mediaBlock = body.blocks.find(function (block) {
        return block.type=='image'
    });
    blog.coverMedia = mediaBlock ? mediaBlock.data.file.url : ''; 

    let searchForText = element => element.type == 'paragraph';
    let postTeaser = body.blocks.find(searchForText);

    if(postTeaser && postTeaser.data.text != 'Click here to get started...'){
        postTeaser = postTeaser.data.text          
    } else {
        postTeaser = `Check out this post by a member of our community`
    }

    blog.excerpt = smartTrim(postTeaser, 320, ' ', ' ...');
    blog.mdesc = stripHtml(postTeaser.substring(0, 160));

    blog.postedBy = req.user._id;
    console.log('req.user._id on server when saving blogpost: ',req.user._id);
    
    const html = edjsParser.parse(body);
    console.log('html: ',html);
    blog.html = html.join('');
    // categories and tags
    // let arrayOfCategories = categories && categories.split(',');
    // let arrayOfTags = tags[0];
    //add shop to blog record
    Shop.findOne({ shopify_domain: req.query.shop}).exec((err, shop) => {
       console.log('shop in function to send Email Alert and add Shop reference', shop)
       if(shop && shop._doc && !shop._doc.postModeration){
            blog.hidden = false;
       }
       
       if(!title){
            // title = translations['NewPostByMember'][shop ? shop.language : 'English'];
            title = '';
            blog.slug = makeid(8).toLowerCase();
            blog.slug = blog.slug.replace(/\./g,' ').replace(/;/g, "").replace(/:/g, "").replace(/!/g, "");
       } else {
            blog.slug = slugify(title.replace(/["']/g, "")).toLowerCase();
            blog.slug = blog.slug.replace(/\./g,' ').replace(/;/g, "").replace(/:/g, "").replace(/!/g, "");
       }

        blog.title = title;
        blog.mtitle = `${title} | ${process.env.APP_NAME}`;

        blog.save((err, result) => {
            if (err) {
                console.log('error saving post',err)
                return res.status(400).json({
                    error: errorHandler(err)
                });
            }
            console.log('post saved successfully',result);

           let storeAdminName = shop && shop._doc && shop._doc.extraShopifyData && shop._doc.extraShopifyData[0] && shop._doc.extraShopifyData[0].name ? shop._doc.extraShopifyData[0].name : 'you';
           let appSlug = process.env.NODE_ENV == 'development' ? 'community-2' : 'social-king';
           
           if(shop && shop._doc && shop._doc.postModeration){
               // sendMail() - to do - abstract this away to another function/email folder

               const emailData = {
                  to: shop && shop._doc && shop._doc.extraShopifyData && shop._doc.extraShopifyData[0] && shop._doc.extraShopifyData[0].email ? shop._doc.extraShopifyData[0].email : 'kramer1346@gmail.com',
                  from: 'help@socialking.app',
                  subject: `Review A New Community Post!`,
                  text: `Hey ${storeAdminName}, \n Looks like a new post has been submitted via your Community Network`,
                  html: `
                      <h4>Hey ${storeAdminName},</h4>
                      <p>A New Customer Post has been Submitted and is <a href='https://${blog.shopifyDomain}/admin/apps/${appSlug}/manage/manage-posts'>pending review here</a></p>
                      <hr />
                  `
               };

               console.log('emailData in Sendgrid Email Notification Function', emailData);

               sgMail.send(emailData).then(sent => {
                    console.log('email alert sent to ', req.query.shop)
               })

           }           
           
           Blog.findByIdAndUpdate(result._id, { $set: { shopPostedAt: [shop._id] } }, { new: true }).exec(
                (err, result) => {
                    if (err) {
                        console.log('ran error in block when trying to save blog reference to shop')
                        return res.status(400).json({
                            error: errorHandler(err)
                        })
                    }
                    console.log('Shop added to blog record');
                    tags.forEach((tag, index)=>{
                        Blog.findByIdAndUpdate(result._id, { $push: { tags: tag } }, { new: true }).exec(
                            (err, result) => {
                                if (err) {
                                    return res.status(400).json({
                                        error: errorHandler(err)
                                    });
                                } else {
                                    console.log('saved tag:', tag) 
                                }
                            }
                        );
                    })
                    if(shop && shop._doc && !shop._doc.postModeration){
                        let message = translations['PostLive'][shop ? shop.language : 'English']
                        if(blog.shopifyDomain.includes('skordo')){
                           message =  `<p>
                              Thank you for submitting your post! 
                              Explore others’ posts and various cooking topics on our <a href='/community/connect'>community page</a>.
                            </p>`
                        } else {
                            message = `<a href='https://${blog.shopifyDomain}${process.env.PROXY_ROUTE}/blog/${blog.slug}'>${message}</a>`
                        }
                        res.send({message});
                    } else {
                        let message = translations['PostPendingReview'][shop ? shop.language : 'English']
                        if(blog.shopifyDomain.includes('skordo')){
                           message =  `<p>
                              Thank you for submitting your post! 
                              Explore others’ posts and various cooking topics on our <a href='/community/connect'>community page</a>.
                            </p>`
                        }
                        res.send({message});
                    }
                }
            );        
        });
    });
};


exports.createComment = (req, res) => {
    res.setHeader('content-type', 'text/javascript')
    let { body } = req.body;
    console.log('req.body in comment create function: ',req.body);
    console.log('req.profile in comment create function: ',req.profile);
    console.log('req.query in comment create function: ',req.query);

    if (body.blocks === undefined || body.blocks.length == 0) {
        return res.status(400).json({
            error: 'Content is required'
        });
    }

    let comment = new Comment();
    comment.shopifyDomain=req.query.shop;
    comment.body = body;
    let mediaBlock = body.blocks.find(function (block) {
        return block.type=='image'
    });
    comment.coverMedia = mediaBlock ? mediaBlock.data.file.url : ''; 

    comment.postSlug = req.query.slug;
    comment.postedBy = req.user._id;
    
    const html = edjsParser.parse(body);
    console.log('html: ',html);
    comment.html = html.join('');
    // categories and tags
    // let arrayOfCategories = categories && categories.split(',');
    // let arrayOfTags = tags[0];
    Shop.findOne({ shopify_domain: req.query.shop}).exec((err, shop) => {
        console.log('shop in createComment function', shop);
        if(shop && !shop.commentModeration){
            comment.hidden = false;
        }

        comment.save((err, result) => {
            if (err) {
                console.log('error saving comment',err)
                return res.status(400).json({
                    error: errorHandler(err)
                });
            }
            console.log('comment saved successfully',result);
        
           Comment.findByIdAndUpdate(result._id, { $set: { shopPostedAt: [shop._id] } }, { new: true }).exec(
                (err, result) => {
                    if (err) {
                        console.log('ran error in block when trying to save comment reference to shop')
                        return res.status(400).json({
                            error: errorHandler(err)
                        })
                    }
                    console.log('Shop added to comment record');
                    if(shop && !shop.commentModeration){
                        res.send({message: comment.html});
                    } else {
                        let message = translations['CommentPendingReview'][shop ? shop.language : 'English']
                        res.send({message});                        
                    }
                }
            );        
        });
    });
};

exports.getEmojis = (req,res) => {
    console.log('getEmojis controller func ran')
    res.setHeader('content-type', 'text/javascript')
    
    let {slug, shop} =req.query;

    Emoji.find({shopifyDomain: shop})
            .populate('postedBy', '_id about storeFavorites cover_photo name username trackingID')
            .exec((err, emojis) => {
                if (err) {
                    return res.json({
                        error: errorHandler(err)
                    });
                } else {
                    console.log('emojis in getEmojis func',emojis);
                    res.send(emojis);
                }
            })
}

exports.addEmoji = (req, res) => {
    res.setHeader('content-type', 'text/javascript')
    
    console.log('req.body in emoji create function: ',req.body);
    console.log('req.profile in emoji create function: ',req.profile);
    console.log('req.query in emoji create function: ',req.query);

    let emoji = {};

    emoji.shopifyDomain=req.query.shop;
    emoji.emoji = req.query.emoji;
    
    emoji.postSlug = req.query.slug;
    emoji.postedBy = req.user._id;
    
    Emoji.findOneAndUpdate({postSlug: emoji.postSlug, postedBy: emoji.postedBy}, emoji, {upsert: true}, function(err, result) {
        if (err) return res.send(500, {error: err});
        console.log('emoji saved/updated successfully');

        //add shop to emoji record
        Shop.findOne({ shopify_domain: req.query.shop}).exec((err, shop) => {
           console.log('shop in function to add Shop reference', shop)
           Emoji.findByIdAndUpdate(result._id, { $set: { shopPostedAt: [shop._id] } }, { new: true }).exec(
                (err, result) => {
                    if (err) {
                        console.log('ran error when trying to save emoji reference to shop')
                        return res.status(400).json({
                            error: errorHandler(err)
                        })
                    }
                    console.log('Shop added to emoji record');
                    res.send({message: 'Emoji added successfully'});
                }
            );        
        });
    });      
};



// list, listAllBlogsCategoriesTags, read, remove, update

exports.listForSitemap = (req, res) => {
    console.log('req.query in listForSitemap', req.query);

    Shop.findOne({shopify_domain: req.query.shop}).exec((err, shop) => {
        if (err) {
            return res.status(400).json({
                error: errorHandler(err)
            });
        }
        
        let shopId = shop._id;
        
        Blog.find({ shopPostedAt: shopId })
        .sort({ createdAt: -1 })
        .select('slug updatedAt')
        .exec((err, blogs) => {
            if (err) {
                return res.json({
                    error: errorHandler(err)
                });
            }
            
            User.find({ "profile": { "$regex": req.query.shop, "$options": "i" }})
                .select('username profile updatedAt')
                .exec((err, users) => {
                    if (err) {
                        return res.json({
                            error: errorHandler(err)
                        });
                    }

                    Tag.find({shop: req.query.shop})
                        .select('slug updatedAt')
                        .exec((err, tags) => {
                            if (err) {
                                return res.json({
                                    error: errorHandler(err)
                                });
                            }
                            let data = {};
                            
                            data.tags=tags; 
                            data.users=users;
                            data.blogs=blogs;

                            let latestPost = 0;
                          let latestProfile = 0;
                          let latestTag = 0;


                          let projectsXML = "";
                          let profilesXML = "";
                          let tagsXML = "";
                          let DOMAIN = req.query.shop;


                          data.tags.map(tag => {
                            const tagDate = tag.updatedAt;
                            if (!latestTag || tagDate > latestTag) {
                              latestTag = tagDate;
                            }

                            const tagURL = `${DOMAIN}/community/connect/tags/${tag.slug}`;
                            tagsXML += `
                              <url>
                                <loc>${tagURL}</loc>
                                <lastmod>${tagDate}</lastmod>
                                <priority>0.80</priority>
                              </url>`
                          });

                          data.users.map(user => {
                            const profileDate = user.updatedAt;
                            if (!latestProfile || profileDate > latestProfile) {
                              latestProfile = profileDate;
                            }

                            const profileURL = `${DOMAIN}/community/connect/user/${user.username}`;
                            profilesXML += `
                              <url>
                                <loc>${profileURL}</loc>
                                <lastmod>${profileDate}</lastmod>
                                <priority>0.80</priority>
                              </url>`
                          });

                          data.blogs.map(post => {
                            const postDate = post.updatedAt;
                            if (!latestPost || postDate > latestPost) {
                              latestPost = postDate;
                            }

                            const projectURL = `${DOMAIN}/community/connect/blog/${post.slug}`;
                            projectsXML += `
                              <url>
                                <loc>${projectURL}</loc>
                                <lastmod>${postDate}</lastmod>
                                <priority>0.80</priority>
                              </url>`
                          });

                          let theSitemap = `<?xml version="1.0" encoding="UTF-8"?>
                            <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
                              <url>
                                <loc>${DOMAIN}/community/connect</loc>
                                <priority>0.90</priority>
                              </url>
                              ${tagsXML}
                              ${profilesXML}
                              ${projectsXML}
                            </urlset>`
                            res.setHeader("Content-Type", "text/xml");
                            res.write(theSitemap);
                            res.end();
                    });
             });        
        });

    });
};


exports.listAllBlogsCategoriesTags = async (req, res) => {
    console.log('ran listAllBlogsCategoriesTags function on server with req.query', req.query);
    let limit = req.body.limit ? parseInt(req.body.limit) : 9;
    let skip = req.body.skip ? parseInt(req.body.skip) : 0;

    let blogs;
    let categories;
    let tags;

    //listByUser from Shopify Admin App
    console.log('req.body', req.body);
    let shopName = req.query.shop;
    console.log('shopName',shopName);
    Shop.findOne({shopify_domain: shopName}).exec((err, shop) => {
        if (err) {
            return res.status(400).json({
                error: errorHandler(err)
            });
        }
        
        let shopId = shop ? shop._id : '5f1e6a95cae9586963ac9c24';
        Blog.find({ hidden: false, shopPostedAt: shopId, archivedByUser: { $ne: true } })
        .sort({createdAt: -1})
        .populate('tags', '_id name slug')
        .populate('postedBy', '_id name username profile cover_photo')
        .sort({ total_ratings: -1 })
        .skip(skip)
        .limit(limit)
        .select('_id commentCount shopifyDomain title excerpt cover_photo coverMedia slug product_imgurl product_summary mdesc autoGenerated categories tags postedBy createdAt updatedAt')
        .exec((err, data) => {
            if (err) {
                return res.json({
                    error: errorHandler(err)
                });
            }
            blogs = data; // blogs
                // get all tags
                Tag.find({shop: shopName}).exec((err, t) => {
                    if (err) {
                        return res.json({
                            error: errorHandler(err)
                        });
                    }
                    tags = t;
                    // return all blogs categories tags
                    let blogsToReturn = [];

                    blogs.forEach((blog, index)=>{
                        Comment.count({shopifyDomain: blog.shopifyDomain, postSlug: blog.slug})
                        .exec((err, data) => {
                            console.log('data in commentCount func', data)
                            let indBlog = JSON.parse(JSON.stringify(blogs[index]));
                            indBlog.commentCount = data;
                            blogsToReturn.push(indBlog)
                            console.log('indBlog',indBlog)
                            if(blogs.length-1==index){
                                if(!shop){
                                    res.setHeader('content-type', 'text/html');
                                    return res.send(`<!doctype html><html lang="en">`+blogsList({ shop, blogs: blogsToReturn, tags, size: blogs.length })+`</html>`);
                                }
                                res.send(blogsList({ shop, blogs: blogsToReturn, tags, size: blogs.length }));
                            }
                        })    
                    })

                    
                });
        });
    });    
};

exports.read = (req, res) => {
    console.log('read function ran in controller')
    const slug = req.params.slug.toLowerCase();
    if(slug=='undefined'){
        console.log('shopify sent an extra server request for some reason');
        return res.send({message: 'all good'});
    }
    
     Shop.findOne({shopify_domain: req.query.shop})
        .select("-accessToken")   
        .exec((err, shop) => {
            if (err) {
                return res.json({
                    error: errorHandler(err)
                });
            }
            Comment.find({postSlug: slug, shopifyDomain: req.query.shop, hidden: false})
            .populate('postedBy', '_id about storeFavorites cover_photo name username trackingID')
            .exec((err, comments) => {
                if (err) {
                    return res.json({
                        error: errorHandler(err)
                    });
                }
                 Blog.findOne({ slug, shopifyDomain: req.query.shop })
                    .populate('shop', '_id headerImageURL iconImageURL')
                    .populate('tags', '_id name slug')
                    .populate('postedBy', '_id about storeFavorites cover_photo name username trackingID')
                    .select('_id coverMedia title about storeFavorites hidden cover_photo html body selectedProducts product_rating total_ratings autoGenerated slug mtitle mdesc tags postedBy trackingID createdAt updatedAt')
                    .exec((err, blog) => {
                        if (err) {
                            return res.json({
                                error: errorHandler(err)
                            });
                        }

                        console.log('blog returned from query',blog);

                            if(blog){
                                User.findOne({ _id: blog.postedBy })
                                .exec((err, user) => {
                                    if (err || !user) {
                                        return res.status(400).json({
                                            error: 'User not found'
                                        });
                                    }

                                    res.send(blogSlug({blog, shop, user, comments}));
                                });
                            } else {
                                res.send(notFound())
                            }
                         
                    });
            })
        });
};

exports.remove = (req, res) => {
    res.setHeader('content-type', 'text/javascript');
    const slug = req.params.slug.toLowerCase();
    Blog.update({slug, shopifyDomain: req.query.shop }, {
        archivedByUser: true
    }, function(err, affected, resp) {
       if (err) {
            return res.json({
                error: errorHandler(err)
            });
        }
       res.json({
            message: 'Post deleted successfully'
        });
    })
};


exports.toggle = (req, res) => {
    const slug = req.params.slug.toLowerCase();

    Blog.findOne({ slug: slug, shopifyDomain: req.query.shop }, function(err, blog) {
        blog.hidden = !blog.hidden;
        blog.save(function(err, updatedBook) {
            if (err) {
                return res.json({
                    error: errorHandler(err)
                });
            }
            res.json({
                message: 'Blog toggled successfully'
            });
        });
    });
}

exports.listRelated = (req, res) => {
    console.log(req.body.blog);
    let limit = req.body.limit ? parseInt(req.body.limit) : 9;
    const { _id, tags, search_keyword } = req.body.blog;

    if(search_keyword){
        Blog.find({ _id: { $ne: _id }, hidden: false, search_keyword: search_keyword })
            .limit(limit)
            .populate('postedBy', '_id name username profile')
            .sort({ total_ratings: -1 })
            .select('title slug autoGenerated product_imgurl mdesc postedBy createdAt updatedAt')
            .exec((err, blogs) => {
                if (err) {
                    return res.status(400).json({
                        error: 'Blogs not found'
                    });
                }
                res.json(blogs);
            });
    } else {
        Blog.find({ _id: { $ne: _id }, hidden: false, tags: { $in: tags } })
            .limit(limit)
            .populate('postedBy', '_id name username profile')
            .select('title slug autoGenerated product_imgurl mdesc postedBy createdAt updatedAt')
            .exec((err, blogs) => {
                if (err) {
                    return res.status(400).json({
                        error: 'Blogs not found'
                    });
                }
                res.json(blogs);
            });
    }
};

//
exports.listSearch = (req, res) => {
    console.log(req.query);
    const { search } = req.query;
    let limit = req.body.limit ? parseInt(req.body.limit) : 35;

    if (search) {
        Blog.find(
            {
                $or: [{ title: { $regex: search, $options: 'i' } }, { body: { $regex: search, $options: 'i' } }],
                hidden: false
            },
            (err, blogs) => {
                if (err) {
                    return res.status(400).json({
                        error: errorHandler(err)
                    });
                }
                res.json(blogs);
            }
        ).limit(limit)
        .sort({ total_ratings: -1 })
        .select('-photo -body');
    }
};

exports.listByUser = (req, res) => {
    console.log('ran list by user function on server');
    res.setHeader('content-type', 'text/javascript');

    User.findOne({ username: req.params.username, shopDomain: req.query.shop }).exec((err, user) => {
        if (err) {
            return res.status(400).json({
                error: errorHandler(err)
            });
        }
        let userId = user._id;
        Blog.find({ postedBy: userId, shopifyDomain: req.query.shop })
            .sort({createdAt: -1})
            .populate('tags', '_id name slug')
            .populate('postedBy', '_id name username')
            .select('_id title slug postedBy hidden createdAt updatedAt')
            .exec((err, data) => {
                if (err) {
                    return res.status(400).json({
                        error: errorHandler(err)
                    });
                }
                res.json(data);
            });
    });
};
