const { header } = require('./components/header');
const { newsFeed } = require('./components/newsFeed');
const { navbar } = require('./components/navbar');
const { newsFeedCSS } = require('./css/newsFeedCSS');
const proxyRoute = process.env.PROXY_ROUTE;

exports.userSlug = ({user, blogs, shop}) => {

    return `
        <link rel="stylesheet" href="https://unpkg.com/purecss@2.0.3/build/pure-min.css" integrity="sha384-cg6SkqEOCV1NbJoCu11+bm0NvBRc8IYLRGXkmNrqUBfTjmMYwNKPWBTIKyw9mHNJ" crossorigin="anonymous">
        <style type="text/css">
            ${newsFeedCSS({shop})}
        </style>
        ${header({user, shop})}
        <div class="community-background">
            <main class="page-width">
                <div class="pure-g">
                    ${newsFeed({user, shop, blogs})}
                    ${navbar({shop, user})}
                </div>
            </main>
        </div>
    
        <script>
            console.log('injected script from server ran');
        </script>`
};