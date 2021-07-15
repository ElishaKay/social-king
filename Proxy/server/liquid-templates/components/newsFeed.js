const proxyRoute = process.env.PROXY_ROUTE;
const backupShopIcon = "https://www.bongiorno.eu/assets/img/facebook/bongiorno.jpg";
const {translations} = require('../../helpers/translations')

exports.newsFeed = ({shop, blogs}) => {
    
    const showEmojis = (blog) => {
        return activeEmojis;
    }

    const showLoadedBlogs = () => {
        console.log('blogs in showLoadedBlogs func: ', blogs)
        
        if(shop.shopify_domain.includes('beforestores')){
            return blogs.map((blog, i) => `
                <div class="pure-u-1">
                    <div class="l-box community-card">
                        <a href="${proxyRoute}/blog/${blog.slug}">
                          ${blog.coverMedia ? "<img class='cover-img' src='"+blog.coverMedia+"'/>" : '<br/>'}
                        </a>
                        
                        <a href="${proxyRoute}/user/${blog.postedBy.username}">
                            <img src="${blog.postedBy && blog.postedBy.cover_photo ? blog.postedBy.cover_photo : backupShopIcon}" 
                              class="community-user-icon" />
                            <div class="community-author">${translations['PostedBy'][shop ? shop.language : 'English']} ${blog.postedBy.name}</div>
                         </a>
                         <a href="${proxyRoute}/blog/${blog.slug}">
                           <h3 class="blog-title">${blog.title}</h3>
                         </a>
                         <p class="blog-excerpt">${blog.excerpt}</p>
                        <a href="${proxyRoute}/blog/${blog.slug}">
                          <p class="community-read-more">READ MORE >></p>    
                        </a>
                        
                     </div>
                </div>
            `).join('');
        } else {
            return blogs.map((blog, i) => `
                <div class="pure-u-1">
                    <div class="l-box community-card">
                        <a href="${proxyRoute}/user/${blog.postedBy.username}">
                            <img src="${blog.postedBy && blog.postedBy.cover_photo ? blog.postedBy.cover_photo : backupShopIcon}" 
                              class="community-user-icon" />
                            <div class="community-author">${translations['PostedBy'][shop ? shop.language : 'English']} ${blog.postedBy.name}</div>
                         </a>
                        <a href="${proxyRoute}/blog/${blog.slug}">
                            <h3>${blog.title}</h3>
                            ${blog.coverMedia ? "<img class='cover-img' src='"+blog.coverMedia+"'/>" : '<br/>'}
                            <p>${blog.excerpt}</p>
                        </a>
                       <div class='text'><p class='community-post-slug-${blog.slug} community-instant-post community-reactions'></p></div>
                       <a href="${proxyRoute}/blog/${blog.slug}">
                          <p>${blog.commentCount==null ? 'There may or may not be comments here': blog.commentCount} 
                          ${ blog.commentCount!=null ? (blog.commentCount!=1 ? 'comments' : 'comment'): ''}</p>
                       </a>
                       <a href='https://${shop.shopify_domain+proxyRoute}/user/profile?slug=${blog.slug}&email={{ customer.email }}&name={{ customer.name }}&hash={{ customer.email | append: "somecrazyhash" | md5 }}#/add-comment'>
                            <input type="text" class="community-instant-post" placeholder="${translations['AddComment'][shop ? shop.language : 'English']}" />
                        </a>
                     </div>
                </div>
            `).join('');
        }
    };
    
    const loadHTML = () => {
        
        if(shop.shopify_domain.includes('beforestores')){
          return `
            <div class="community-pad-20">
                          <div class="community-card say-something">
                              <div class="community-card-body">
                                  <a href='https://${shop ? shop.shopify_domain+proxyRoute : 'social-king-app.myshopify.com'+proxyRoute}/user/profile?email={{ customer.email }}&name={{ customer.name }}&hash={{ customer.email | append: "somecrazyhash" | md5 }}#/create-new-post'>
                                      <input type="text" class="community-instant-post" placeholder="Say Something..." />
                                  </a>
                              
                              </div>
                          </div>
                          <div class="community-card">
                            <div class="posts-container">
                              ${showLoadedBlogs()}
                            </div>
                          </div>
                      </div>
          `
        } else {
          return `<div class="pure-u-md-7-12 pure-u-sm-1 community-newsfeed-box">
                      <div>
                          <div class="community-card">
                              <div class="community-card-body">
                                  <a href='https://${shop ? shop.shopify_domain+proxyRoute : 'social-king-app.myshopify.com'+proxyRoute}/user/profile?email={{ customer.email }}&name={{ customer.name }}&hash={{ customer.email | append: "somecrazyhash" | md5 }}#/create-new-post'>
                                      <input type="text" class="community-instant-post" placeholder="${translations['CreatePost'][shop ? shop._doc.language : 'English']}" />
                                  </a>
                              
                              </div>
                          </div>
                          <div>
                            <div class="posts-container">
                              ${showLoadedBlogs()}
                            </div>
                          </div>
                      </div>
                  </div>` 
        }
    };

    return `
        ${loadHTML()}

        <script src='https://cdn.jsdelivr.net/npm/emoji-button@2.2.2/dist/index.min.js'></script> 
        <script src='https://cdn.jsdelivr.net/npm/axios@0.20.0/dist/axios.min.js'></script>        

        <script>                
            axios({
              method: 'post',
              url: '${proxyRoute}/blog/emojis'
            }).then((response) => {
              console.log('emoji Data:  ',response.data);
              let emojiData = response.data;

              let communityReaction = document.querySelectorAll('.community-reactions');

              console.log('')

              communityReaction.forEach(item => {
                let blogSlug = item.classList[0].split('community-post-slug-')[1];
                console.log('blogSlug', blogSlug);

                let postEmojis = emojiData.filter((reaction)=>reaction.postSlug==blogSlug);

                console.log('Emojis of the post ' + blogSlug + postEmojis);

                let input = document.querySelector('.'+item.classList[0]);

                let emojiSummary = [];

                postEmojis.forEach((reaction)=>{
                  emojiSummary.push({name: reaction.postedBy ? reaction.postedBy.name : 'New Shopper', emoji: reaction.emoji}); 
                })

                if (emojiSummary === undefined || emojiSummary.length == 0) {
                    input.innerHTML = '😌'
                } else {
                    input.innerHTML = emojiSummary.map((reaction)=>{
                        return reaction.name + ': ' + reaction.emoji;
                    }).join(', ');
                }

                item.addEventListener('click', event => {
                  console.log('item.classList[0]: ',item.classList[0])

                  let picker = new EmojiButton({
                      position: 'auto',
                      rows: 8,
                      showRecents: true
                  })

                  picker.on('emoji', function(emoji){
                      let userName = '{{ customer.name }}';
                      if(input.innerHTML.includes('Add Emoji')){
                          emojiSummary.push({name: userName, emoji: emoji})
                      } else if(!input.innerHTML.includes('{{ customer.name }}')){
                          emojiSummary.push({name: userName, emoji: emoji})
                      } else {
                        console.log('postEmojis: ',postEmojis)
                        let reactionToReplace = emojiSummary.find((reaction)=>{
                         return reaction.name == userName 
                        })
                        
                        let index = emojiSummary.indexOf(reactionToReplace);

                        emojiSummary[index] = {name: userName, emoji: emoji};

                        console.log('emojiSummary array after updating: ', emojiSummary)
                      }

                      input.innerHTML = emojiSummary.map((reaction)=>{
                          return reaction.name + ': ' + reaction.emoji;
                      }).join(', ');
                      
                      axios({
                        method: 'post',
                        url: '${proxyRoute}/user/blog/emoji?slug='+blogSlug+'&emoji='+emoji+'&email={{ customer.email }}&name={{ customer.name }}&hash={{ customer.email | append: 'somecrazyhash' | md5 }}',
                        data: {
                          firstName: 'Finn',
                          lastName: 'Williams'
                        }
                      }).then((response) => {
                        console.log(response.data);
                        if(response.data.redirectTo!=undefined){
                          window.location.href = response.data.redirectTo; 
                        }
                      }, (error) => {
                        console.log(error);
                      });
                  })

                  picker.pickerVisible ? picker.hidePicker() : picker.showPicker(input)
                  
                })
              })

            }, (error) => {
              console.log(error);
            });

        </script>
        `
};


