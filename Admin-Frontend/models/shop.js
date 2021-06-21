const mongoose = require('mongoose');

const Shop = mongoose.Schema({
	  shopId: Number,
	  shopify_domain: 
	  	{ type: String, 
	  	  unique: true,
          index: true },
	  name: String,
	  domain: String,
	  supportEmail: String,
	  nonce: String,
	  accessToken: String,
	  isActive: { type: Boolean, default: false },
	  // tribe-squared fields
	  shopUrl: String,
	  shopifyToken: String,
	  shopifyScope: String,
	  headerImageURL: { 
            type: String, 
            default: 'https://socialking.app/proxy/images/uploads/community-dev-store.myshopify.com-1597050539511.jpeg' 
        },
	  iconImageURL: { 
            type: String, 
            default: 'https://socialking.app/proxy/images/uploads/community-dev-store.myshopify.com-1597050539510.png' 
        },
	  aboutCommunity: { 
            type: String, 
            default: 'Welcome to Our Community - a place for shoppers to share their voices.' 
        },
	  communityName: { 
            type: String, 
            default: 'Our Community' 
      },
	  primaryColor: { 
            type: String, 
            default: '#26b598' 
      },
	  backgroundColor: { 
            type: String, 
            default: '#f6f7f8' 
      },
      buttonsColor: { 
            type: String, 
            default: '#26b598' 
      },
      CSSCode: { 
	  	type: String, 
	  	default: "\n #new-post {color: black;} \n community-pad-20 { font-color: black; min-width: 300px; } \n .community-card-body {color: black;}\n .codex-editor__redactor { padding:5%; color: black; padding-bottom: 120px !important; background: #f6f7f8; }\n            .community-background { padding-top:20px; overflow: hidden; }\n   .community-settings-view .community-card {margin-right: 15%;} \n    .l-box { padding:1em; }\n            .tag-btn { margin-top: 1em;\n                      margin-bottom: 1em;\n                      background-color: rgb(160, 92, 123); }\n            .tag-btn:hover { background-color: bone; }\n            .community-user-icon { border:4px solid #fff;border-radius:100%;max-width:75px !important;margin-top:-10px; }\n            .community-icon { border:4px solid #fff;border-radius:100%;max-width:75px !important;margin-top:-10px; }\n            .community-header { padding-top:120px;margin-top:-55px;background-repeat:no-repeat;background-position:center;background-size:cover }\n            .community-header-title { background:#fff; }\n            .community-header-title-box { margin-left: 10%; display:flex }\n            .community-header-title .community-h2 { display:inline-block;margin-left:20px;font-size:30px;font-weight:bold;color:#000;padding:10px 0; }\n            .community-card { letter-spacing: .5px; border:1px solid #ccc;border-radius:4px;margin-bottom:20px;background:#fff }\n            .community-card-header { letter-spacing: .5px; color:white;padding:10px;font-weight:bold; }\n            .community-card-body { letter-spacing: .4px; padding:30px }\n            .community-post-body { letter-spacing: .35px;}\n            .community-post-body h2 { color: black; font-weight: bold;}\n            .community-post-body button { white-space: normal; }\n            .community-card a { white-space: normal; }\n            .community-letter-spacing { letter-spacing: .4px; }\n            @media only screen \n            and (min-device-width: 600px)\n             { .community-pad-20 { padding:10px 20px 20px 20px } }\n            .community-hr { margin:20px 0 }\n            .community-hr-minimal { margin:8px 0 }\n            .community-full-width { width: 100% }\n            .community-instant-post { width:100%; background: #f6f7f8; padding:10px }\n            .community-instant-post:hover, .community-instant-post:focus { background:#fff }\n            .community-author { color:#969696;font-size:12px;margin-bottom:5px }\n            .community-card h3 { font-size:20px;margin-bottom:8px }\n            .community-card p { margin-bottom:8px }\n            .community-card a { color:#383838; text-decoration: none;}\n            .community-card-comments { font-size:12px;font-weight:bold; }\n            .community-pad-left-10 { padding-left:10px }\n            .community-bold { font-weight:bold }\n            .community-admin-padding { padding:10px 20px 20px 20px }\n            .community-button-danger {  background: rgb(202, 60, 60); color: white; border-radius: 4px; text-shadow: 0 1px 1px rgba(0, 0, 0, 0.2);}\n            .community-button-secondary { margin-top: 1em;\n                  margin-bottom: 1em;\n                  margin-right: 1em;\n                  margin-left: 1em; background: rgb(160,92,123); color: white; border-radius: 4px; text-shadow: 0 1px 1px rgba(0, 0, 0, 0.2); }\n            .community-checkbox { float:left;margin-right:30px }\n            .community-newsfeed-box {width:100%}\n            .community-reactions:hover{ cursor: pointer; }\n            .emoji-picker { z-index: 100;}\n            .community-admin-btn {color:white;}\n            .cover-img { max-width: 100%; }\n            #profile-photo img { max-width: 100%; max-height: 300px; padding-bottom: 30px; }\n            .community-card p,h3,h4,h5,h6,h7 { font-size: 15px; color: black; }"
	  },
      charge_id:  { 
	  	  type: String, 
	  	  default: '' 
	  },
	  recurring_application_charge: {
  	      type: Array
	  },
	  extraShopifyData: {
  	      type: Array
	  },
	  postModeration: { 
		  type: Boolean, 
		  default: true 
      },
      commentModeration: { 
		  type: Boolean, 
		  default: true 
      },
      language: { 
        type: String, 
        default: 'English' 
	  }
  },
  { timestamps: true }
);

module.exports = mongoose.model('Shop', Shop);
