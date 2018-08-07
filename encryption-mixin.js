const R = require('ramda');
const crypto = require('crypto');
const loopback = require('loopback');

const getOpt = options => ({
    fields: options.fields || [],
    secretKey: options.secretKey || loopback.wpms.configs.secretKey,
    encryptionAlgorithm: options.encryptionAlgorithm || 'aes-128-ecb'
});

const convertCryptKey = strKey => {
    strKey = crypto.createHash('md5').update(strKey).digest('hex');
    strKey = new Buffer(strKey);
    let newKey = new Buffer(R.repeat(0, 16));
    for (let i = 0; i < strKey.length; i++)
        newKey[i % 16] ^= strKey[i]; // jshint ignore:line
    return newKey;
};

const encrypt = (text, options) => {
    let cipher = crypto.createCipheriv(options.encryptionAlgorithm, convertCryptKey(options.secretKey), '');
    let crypted = cipher.update(text.toString(), 'utf8', 'hex');
    crypted += cipher.final('hex');
    return crypted.toUpperCase();
};

const decrypt = (text, options) => {
    let decipher = crypto.createDecipheriv(options.encryptionAlgorithm, convertCryptKey(options.secretKey), '');
    let dec = decipher.update(text, 'hex', 'utf8');
    dec += decipher.final('utf8');
    return dec;
};


const encryptRecursive = (data, doEncrypt, options) => {
    if ('string' === typeof data || 'number' === typeof data)
        return doEncrypt ? encrypt(data, options) : data;

    let filterKeys = R.keys(data);

    R.forEach(key => {
        doEncrypt = R.contains(key, options.fields);

        if (Array.isArray(data[key])) {
            data[key] = R.map(item => encryptRecursive(item, doEncrypt, options), data[key]);
        } else {
            data[key] = encryptRecursive(data[key], doEncrypt, options);
        }

    }, filterKeys);
    return data;
};

module.exports = (Model, options) => {

    //GDPR encrypting
    Model.observe('persist', (ctx, next) => {
        let opt = getOpt(options);
        if (ctx.data) {
            let dataFields = R.keys(ctx.data);
            let fieldsForEncrypt = R.intersection(dataFields, opt.fields);

            R.forEach(field => {
                if (ctx.data[field])
                    ctx.data[field] = encrypt(ctx.data[field], opt);
            }, fieldsForEncrypt);
        }
        next();
    });

    //GDPR encrypting
    Model.observe('access', (ctx, next) => {
        let opt = getOpt(options);
        if (ctx.query && ctx.query.where) {
            ctx.query = R.clone(ctx.query);
            ctx.query.where = encryptRecursive(ctx.query.where, false, opt);
        }
        next();
    });

    //GDPR decrypting
    Model.observe('loaded', (ctx, next) => {
        let opt = getOpt(options);
        let dataForEncrypt = ctx.data || ctx.instance.toJSON();
        let dataForResponse = ctx.data || ctx.instance;
        if (dataForEncrypt) {
            let dataFields = R.keys(dataForEncrypt);
            let fieldsForDecrypt = R.intersection(dataFields, opt.fields);

            R.forEach(field => {
                if (dataForEncrypt[field])
                    dataForResponse[field] = decrypt(dataForEncrypt[field], opt);
            }, fieldsForDecrypt);
        }
        next();
    });
};
