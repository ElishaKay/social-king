const Koa = require('koa');
const cors = require('@koa/cors');
var https = require('https');
var http = require('http');
const { default: enforceHttps } = require('koa-sslify');
const next = require('next');
const { default: createShopifyAuth } = require('@shopify/koa-shopify-auth');
const dotenv = require('dotenv');
const { verifyRequest } = require('@shopify/koa-shopify-auth');
const session = require('koa-session');
const { ApiVersion } = require('@shopify/koa-shopify-graphql-proxy');
const { default: graphQLProxy } = require('@shopify/koa-shopify-graphql-proxy');
dotenv.config();
const port = parseInt(process.env.PORT, 10) || 9000;
const dev = process.env.NODE_ENV !== 'production';
const app = next({ dev });
const handle = app.getRequestHandler();
const Router = require('koa-router');
const processPayment = require('./server/router');
const helloMessage = require('./server/router');
const { SHOPIFY_API_SECRET_KEY, SHOPIFY_API_KEY } = process.env;
const crypto = require('crypto');
const cookie = require('cookie');
const nonce = require('nonce')();
const querystring = require('querystring');
const request = require('request-promise');
var bodyParser = require('koa-bodyparser');
const apiKey = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXx";
const apiSecret = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
const scopes = 'read_products,write_script_tags,read_script_tags,read_customers, write_customers,read_product_listings,read_orders';
const forwardingAddress = "https://qualzz.com:9000"; 
//const forwardingAddress = "https://18.188.232.26:9000"
const appInstallAddress = "https://qualzz.com/api/user/webhooks/userInStalledApp";
const createUserUrlLink = "https://qualzz.com/api/user/createUser";
 const forgotPasswordUrl = "https://qualzz.com/api/user/forgotPassword";
var fs = require('fs');
var LocalStorage = require('node-localstorage').LocalStorage,
localStorage = new LocalStorage('./scratch');
var email = "";
//var key = fs.readFileSync('/etc/nginx/qualzz.com.key');
//var cert = fs.readFileSync('/etc/nginx/qualzz_ssl.crt');
//var credentials = {key: key, cert: cert};
//var httpsServer = https.createServer(credentials, Koa);
// httpsServer.listen(port,()=>{
//     console.log(`> Ready on http://localhost:${port}`);
//});

app.prepare().then(() => {
   console.log("Started")
    const server = new Koa();
    const router = new Router();
    server.use(enforceHttps({
     port: port
    }));
    server.use(cors());
    server.use(bodyParser());
    server.use(session(server));
    server.keys = ["XXXXXXXXXXXXXXXXXXXXX"];
    router.get('/', processPayment);
    router.get('/hello', async (ctx) => {
      ctx.body = {
        status: 'success',
        message: 'hello, world!'
      };
    })
    module.exports = router;

    router.get('/shopify', (ctx,next) => {
        console.log("ctx -->",ctx.query)
        const shop = ctx.query.shop;
        if (shop) {
            const state = nonce();
            const redirectUri = forwardingAddress + '/shopify/callback';
            const installUrl = 'https://' + shop +
              '/admin/oauth/authorize?client_id=' + apiKey +
              '&scope=' + scopes +
              '&state=' + state +
              '&redirect_uri=' + redirectUri;
            ctx.cookies.set('state', state);
            console.log("install url ---->",installUrl)
            ctx.redirect(installUrl);
        } else {
            return ctx.status(400).send('Missing shop parameter. Please add ?shop=your-development-shop.myshopify.com to your request');
        }
    });




router.get('/shopify/callback', (ctx,next) => {
  console.log("in ctx call",ctx.query);
    const { shop, hmac, code, state } = ctx.query;
    const stateCookie = cookie.parse(ctx.headers.cookie).state;

    if (state !== stateCookie) {
        return ctx.status(403).send('Request origin cannot be verified');
    }

    if (shop && hmac && code) {
        const map = Object.assign({}, ctx.query);
        delete map['signature'];
        delete map['hmac'];
        const message = querystring.stringify(map);
        const providedHmac = Buffer.from(hmac, 'utf-8');
        const generatedHash = Buffer.from(
        crypto
        .createHmac('sha256', apiSecret)
        .update(message)
        .digest('hex'),
        'utf-8'
        );
        let hashEquals = false;
        try {
          hashEquals = crypto.timingSafeEqual(generatedHash, providedHmac)
        } catch (e) {
          hashEquals = false;
        };

        if (!hashEquals) {
          return res.status(400).send('HMAC validation failed');
        }

        const accessTokenRequestUrl = 'https://' + shop + '/admin/oauth/access_token';
        const accessTokenPayload = {
          client_id: apiKey,
          client_secret: apiSecret,
          code,
        };
//    setTimeOut(()=>{
    console.log("near to redirect"+email);

          ctx.redirect('https://app.qualzz.com?email='+email);  
  //    },500);
     //ctx.redirect('http://www.google.com');
    request.post(accessTokenRequestUrl, { json: accessTokenPayload })
    .then((accessTokenResponse) => {
        const accessToken = accessTokenResponse.access_token;
        const createScriptTagUrl = 'https://'+shop+'/admin/script_tags.json';
        const shopRequestHeaders = {
            'X-Shopify-Access-Token': accessToken,
        };
        const scriptTagBody = {"script_tag":
        {            "event": "onload",
            "src": "https://app.qualzz.com/assets/trackingScript/webtracking.js"
        }
        };
        var redirectUrl = 'https://app.qualzz.com?email='+email;   
        const shopRequestUrl = 'https://' + shop + '/admin/shop.json';
        // const saveCustomerUrl = 'http://ec2-18-216-255-14.us-east-2.compute.amazonaws.com:8080/user/webhooks/userInStalledApp';    
        const saveCustomerUrl = appInstallAddress;
        request.get(shopRequestUrl, { headers: shopRequestHeaders })
        .then((shopResponse) => {
    //script tag try 3

            const shopDetail = {
                "shop":{
                    "id":JSON.parse(shopResponse).shop.id,
                    "email":JSON.parse(shopResponse).shop.email,
                    "phone":JSON.parse(shopResponse).shop.phone,
                    "name":JSON.parse(shopResponse).shop.name,
                    "domain":JSON.parse(shopResponse).shop.domain
                }
            }
            console.log(shopDetail.shop.domain+">>>>>>>>>>>>>>>>>>emailemailxxx<<<<<<<<");
            email = shopDetail.shop.email+'&url='+shopDetail.shop.domain;

            console.log(email);
            const createUser = {
                "email":JSON.parse(shopResponse).shop.email,
                "fullName":JSON.parse(shopResponse).shop.name,
                "password":'XXXXXXXXX',
                "shopify":true
            }
            const createUserUrl = createUserUrlLink;
            request.post({
                 url:saveCustomerUrl,
                 body:shopDetail,
                 json:true
            },function(error,response,body){
                if(!error){
                    console.log("success in saving"+error+response+body);
                    request.post({
                        url: createScriptTagUrl,
                        body: scriptTagBody,
                        headers: shopRequestHeaders,
                        json: true
                    }, function( error,response,body){
                    if (ctx) {
                        console.log("before route -->",redirectUrl) 
                        console.log("ctxroute --->",ctx)
                        ctx.redirect(redirectUrl);
                    } else {
                        ctx.body = {
                            status:error.statusCode,
                            message:'error'
                        }
                    }
                    });
                    ctx.redirect('https://app.qualzz.com?email='+email); 
                }
            })
            .catch((error) => {
                res.status(error.statusCode);
            });
            request.post({
            url:createUserUrl,
            body:createUser,
            json:true
            },function(error,response,body){

                if(!error){
                    console.log("success in user creation");


                }else{ 

                    console.log('Error in user creation',error)
                }
            })
            .catch((error)=>{
    //            redirectSite();
                ctx.body ={
                   status:error.statusCode,
                   message:'error'
                }
            })
        })
        .catch((error) => {
            ctx.body = {
                 status:error.statusCode,
                 message:'error'
            }
        });

            function redirectSite(){     
                server.use((ctx,next) => {
                });    
//script tag try 2

            }

        })
        .catch((error) => {
            ctx.body = {
                status:error.statusCode,
                message:'error'
            }
        });
    } else {
        res.status(400).send('Required parameters missing');
    }
});


    //var dummyObj;
    var shopifyObject;
    router.post('/shopify/plan/upgrade',async(ctx)=>{
        console.log("ctx --->",ctx.request.body);
        obj = ctx.request.body.plan;
        shopifyObject = ctx.request.body.userInfo;
        localStorage.setItem('shopifyObject',JSON.stringify(shopifyObject));
       console.log("shopify object is --->",shopifyObject)
        const upgradeUrl= ctx.request.body.url;
//        ctx.redirect('/');
 //       ctx.redirect(upgradeUrl);
        ctx.body = {
            status:"200",
            message:'success'  
    }
    });
//  console.log("shopiufy object--->",shopifyObject)
      obj = {
      name: 'Recurring charge',
      price: 20.01,
      return_url: "https://qualzz.com:9000",
      test: true
    }
//console.log("calling this ... ");
    server.use(
        createShopifyAuth({
            apiKey: "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            secret: "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            scopes: ['write_products', 'read_products'],
            async afterAuth(ctx) {
                const { shop, accessToken } = ctx.session;
                console.log("Object is -->",obj);
//       localStorage.setItem('shopifyObject', shopifyObject)
                ctx.cookies.set('shopOrigin', shop, { httpOnly: false });
                const stringifiedBillingParams = JSON.stringify({
                    recurring_application_charge: obj
                })
                console.log("in --->",obj)
                const options = {
                    method: 'POST',
                    body: stringifiedBillingParams,
                    credentials: 'include',
                    headers: {
                        'X-Shopify-Access-Token': accessToken,
                        'Content-Type': 'application/json',
                    },
                };
                const confirmationURL = await fetch(
                    `https://${shop}/admin/api/2019-04/recurring_application_charges.json`, options)
                    .then((response) => response.json())
                    .then((jsonData) => jsonData.recurring_application_charge.confirmation_url)
                    .catch((error) => console.log('error', error));
                    console.log("Confirmation url",confirmationURL)  
                    ctx.redirect('/');

                ctx.redirect(confirmationURL);             
            },
        }),
    );


    server.use(graphQLProxy({version: ApiVersion.April19}))
    server.use(router.routes());
    // server.use(cors());
    server.use(verifyRequest({authRoute: '/shopify/auth', fallbackRoute: '/shopify/auth'}));
    server.use(async (ctx) => {
        await handle(ctx.req, ctx.res);
        ctx.respond = false;
        ctx.res.statusCode = 200;
        return
    });
    var key = fs.readFileSync('/etc/nginx/qualzz.com.key');
    var cert = fs.readFileSync('/etc/nginx/qualzz_ssl.crt');
    var credentials = {key: key, cert: cert};

    https.createServer(credentials, server.callback()).listen(port);

});    