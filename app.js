const crypto = require('crypto');
const _ = require('lodash');

const replacementContent = 'hmac_content';



function createSHA256Digest(str) {
  if (_.isEmpty(str)) return '';

  let stringBody = JSON.stringify(str);
  console.log("String Body: " + stringBody);
  
  const hash = crypto.createHash('sha256');
  hash.update(stringBody);
  return hash.digest('hex');
}

function createHmacSignature(str, secret) {
  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(str);
  return hmac.digest('hex');
}

function computeRequestSignature(req, secret) {
  const { method, pathWithQuery, body, contentType, date } = req;
  const contentDigest = createSHA256Digest(body);
  const payload = `${method.toUpperCase()}\n${contentType}\n${date}\n${pathWithQuery}\n${contentDigest}`;
  console.log("Payload:\n" + payload);
  return createHmacSignature(payload, secret);
}

function ordered(unordered) {
    return Object.keys(unordered).sort().reduce(
      (obj, key) => { 
        obj[key] = unordered[key]; 
        return obj;
      }, 
      {}
    );
} 

function replaceWithHMAC(content, req, key) {
    let hmac = computeRequestSignature(req, key);
    console.log('hmac_signature: ' + hmac);
    return content.replace(new RegExp(replacementContent, 'g'), hmac);
}



// https://docs.insomnia.rest/insomnia/context-object-reference
module.exports.templateTags = [{
    name: 'hmac',
    displayName: 'hmac',
    description: 'Generated hmac for a request',
    args: [
        /*
        {
            displayName: '',
            description: '',
            type: '',
            defaultValue: 0
        }
        */
    ],
    async run (context) {
        return replacementContent;
    }
}];



module.exports.requestHooks = [
  context => {
    const key = context.request.getEnvironmentVariable('accessKeySecret');
    console.log("Access Key: " + key);

    let method = context.request.getMethod();
    let contentType = context.request.getHeader('Content-Type');
    let date = context.request.getHeader('Date');
    let pathWithQuery = context.request.getUrl();

    let rawBody = context.request.getBody().text;
    let body = rawBody == null ? "" : ordered(JSON.parse(rawBody));
    

    console.log('Inputs:\n');
    console.log(method);
    console.log(contentType);
    console.log(date);
    console.log(pathWithQuery);
    console.log(body);
    

    const req = {
      method,
      contentType,
      date,
      pathWithQuery,
      body
    };


    if (context.request.getUrl() != null && context.request.getUrl().indexOf(replacementContent) !== -1) {
      context.request.setUrl(replaceWithHMAC(context.request.getUrl(), req, key));
    }

    if (context.request.getBody().text != null && context.request.getBody().text.indexOf(replacementContent) !== -1) {
      context.request.setBodyText(replaceWithHMAC(context.request.getBody().text, req, key));
    }

    context.request.getHeaders().forEach(h => {
      if (h.value.indexOf(replacementContent) !== -1) {
        context.request.setHeader(h.name, replaceWithHMAC(h.value, req, key));
      }
    });

    context.request.getParameters().forEach(p => {
      if (p.value.indexOf(replacementContent) !== -1) {
        context.request.setParameter(p.name, replaceWithHMAC(p.value, req, key));
      }
    });
  }
];
