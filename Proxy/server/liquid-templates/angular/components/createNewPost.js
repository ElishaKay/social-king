const proxyRoute = process.env.PROXY_ROUTE;
const {formatQuotes} = require('../../../helpers/formatQuotes');
const {translations} = require('../../../helpers/translations')

module.exports.createNewPost = ({shop, user, tags}) => {

  const displayTags = (data) => data.map((tag, i) => {
      return ''
      return `<form class='form-inline' id='post-tags'><label class='checkbox px-2 pure-checkbox community-checkbox' >                
                  <input type='checkbox' ng-model='tags.${tag.id}'><span class='px-1'> ${tag.name}</span>
              </label></form>
      `;
  }).join(' ')

  const displayTitleInput = () =>{
    return `<div class='form-group'>
              <input
                ng-model='title'
                type='text'
                class='form-control'
                id='titleip'
                name='titleip'
                placeholder='${translations['Title'][shop ? shop.language : 'English']}'
                required
              />
            </div>`
  }

  const sendGUIDownards = () =>{
    return `<style>
              .community-background { padding-top: 140px !important }
            </style>`
  }

  const defaultPrompt = () =>{
    return `<h3> ${translations['WhatsUp'][shop ? shop.language : 'English']}${formatQuotes(user.name) ? 
        ', '+formatQuotes(user.name).split(' ')[0] : '' }?</>                      
          `
  }

  const skordoPrompt = () =>{
    return `<p>
              Hi {{ customer.first_name }}! Share a recipe, a photo of the dish you made, ask a cooking question, or tell a cooking story.
            </p>`
  }

  return `
          ${shop.shopify_domain.includes('beforestores') ? 
                        sendGUIDownards() : ''}  
          <div class='community-card community-create-post-editor'>
               <div id='new-post' class='community-admin-padding' ng-controller='newPostController'>
                    <div id='error-message' class='text-center'>
                      ${ shop.shopify_domain.includes('skordo') ? skordoPrompt() : defaultPrompt() }
                    </div>
                    ${shop.shopify_domain.includes('globalxploration-inc') || shop.shopify_domain.includes('jungle-navigator') ||
                         shop.shopify_domain.includes('polka-dots') ? 
                        displayTitleInput() : ''}
      
                    <div id='editorjs'></div>
                    
                    ${Array.isArray(tags) ? displayTags(tags) : ''}
                      
                    <br/>
                    <div class='pure-u-1'>
                     <div class='community-pad-20'>
                        <button button type='submit' class='community-button-secondary pure-button' data-dismiss='modal' aria-hidden='true'
                          ng-click='submitUserBlogPost()' >${translations['SavePost'][shop ? shop.language : 'English']}</button>
                      </div> 
                    </div>
                </div>
            </div>`
};

module.exports.createNewPostJS = ({shop, tags}) => {
  var tagsModel = {};

  console.log('tags obj: ', tagsModel);
  console.log('tags',tags)

  if(Array.isArray(tags)){
    tags.forEach( function(item){ 
       tagsModel[item.id] = false; 
    });
  }

  return `
    tribeApp.controller('newPostController', function($scope, $http) {
      console.log('newPostController function ran');
      
      $scope.tags = {};
       const editor = new EditorJS({
         data: {
		    blocks: [
		      {
		        type: "paragraph",
		        data: {
		          text:
		            "${translations['ClickHere'][shop ? shop.language : 'English']}"
		        }
		      }
		    ]
  	   },
        autofocus: true,
        tools: {
          header: Header,
          image: {
              class: ImageTool,
              config: {
                endpoints: {
                  byFile: '${proxyRoute}/upload?email={{ customer.email }}&name={{ customer.name }}&hash={{ customer.email | append: 'somecrazyhash' | md5 }}', // Your backend file uploader endpoint
                  byUrl: '${proxyRoute}/upload-image-url', // Your endpoint that provides uploading by Url
                }
              }
            },
          embed: Embed,
          list: {
            class: List,
            inlineToolbar: true,
          },
        },
      });

      $scope.submitUserBlogPost = function(){
        editor
            .save()
            .then((body) => {
              
              console.log('save button clicked');
              console.log('Tags data:', $scope.tags);
              let tagIDs = [];
              for (var prop in $scope.tags) {
                  if (Object.prototype.hasOwnProperty.call($scope.tags, prop)) {
                      tagIDs.push(prop)
                  }
              }
              
              const data = { title: $scope.title, body, tags: tagIDs };

              $http.post('${proxyRoute}/user/blog?email={{ customer.email }}&name={{ customer.name }}&hash={{ customer.email | append: 'somecrazyhash' | md5 }}', data)
                     .success(function(data) {
                      document.getElementById('new-post').innerHTML =
                        '<div class="community-admin-padding"><h3>'+data.message+'</h3></div>';
                      delete $scope.title;    
                })
              .error(function(data) {
                console.log('Error: ' + data);
                let errorMessage = data.error && data.error.toLowerCase().includes('slug_1_shop') ? 'Post Title Already Exists' : data.error;
                document.getElementById('error-message').innerHTML =
                 '<h3 style="color:red;">'+errorMessage+'</h3>';
               });
            })
            .catch((err) => {
              console.log(err);
            });
      }
    });
  `
}
