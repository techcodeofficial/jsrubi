const cryptoJS = require('crypto-js')
const crypto = require('crypto');
const RSA = require('node-rsa');
const request = require('sync-request');
function replaceCharAt(e, t, i) {
    return e.substring(0, t) + i + e.substring(t + i.length);
}
function secret(e) {
    const t = e.substring(0, 8);
    const i = e.substring(8, 16);
    let n = e.substring(16, 24) + t + e.substring(24, 32) + i;
    let s = 0;
    while (s < n.length) {
        let char = n[s];
        if (char >= '0' && char <= '9') {
            const t = String.fromCharCode((char.charCodeAt(0) - '0'.charCodeAt(0) + 5) % 10 + '0'.charCodeAt(0));
            n = replaceCharAt(n, s, t);
        } else {
            const t = String.fromCharCode((char.charCodeAt(0) - 'a'.charCodeAt(0) + 9) % 26 + 'a'.charCodeAt(0));
            n = replaceCharAt(n, s, t);
        }
        s += 1;
    }
    return n;
}
class Encryption {
    constructor(auth, private_key = null) {
        this.auth = auth;
        this.key = Buffer.from(secret(auth), "utf-8").toString();
        this.iv = "00000000000000000000000000000000"
        if (private_key) {
            this.keypair = private_key.replace(/\\n/g, '\n');
        }
    }
    static changeAuthType(auth_enc) {
        let n = "";
        const lowercase = "abcdefghijklmnopqrstuvwxyz";
        const uppercase = lowercase.toUpperCase();
        const digits = "0123456789";
        for (let s of auth_enc) {
            if (lowercase.includes(s)) {
                n += String.fromCharCode(((32 - (s.charCodeAt(0) - 97)) % 26) + 97);
            } else if (uppercase.includes(s)) {
                n += String.fromCharCode(((29 - (s.charCodeAt(0) - 65)) % 26) + 65);
            } else if (digits.includes(s)) {
                n += String.fromCharCode(((13 - (s.charCodeAt(0) - 48)) % 10) + 48);
            } else {
                n += s;
            }
        }
        return n;
    }
    encrypt(text) {
        const keyHex = cryptoJS.enc.Utf8.parse(this.key);
        const ivHex = cryptoJS.enc.Hex.parse(this.iv);
        const encrypted = cryptoJS.AES.encrypt(text, keyHex, {
            iv: ivHex,
        });
        return encrypted.toString();
    }
    decrypt(text) {
        const keyHex = cryptoJS.enc.Utf8.parse(this.key);
        const ivHex = cryptoJS.enc.Hex.parse(this.iv);

        try {
            const decrypted = cryptoJS.AES.decrypt(text, keyHex, {
                iv: ivHex,
            });
            const decryptedText = decrypted.toString(cryptoJS.enc.Utf8);
            return decryptedText;
        } catch (error) {
            console.error("Decryption failed:", error.message);
            return null;
        }
    }
    makeSignFromData(data) {
        try {
            const signer = crypto.createSign('RSA-SHA256');
            signer.update(data);
            const signature = signer.sign(this.keypair, 'base64');
            return signature;
        } catch (e) {
            console.log(e.message)
        }
    }
    decryptRsaOaep(privateKey, data_enc) {
        const keyPair = crypto.createPrivateKey(privateKey);
        const dec = crypto.privateDecrypt({
            key: keyPair, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
        }, Buffer.from(data_enc, 'base64'));
        return dec.toString('utf-8');
    }
    static rsaKeyGenerate() {
        const {
            publicKey,
            privateKey
        } = crypto.generateKeyPairSync('rsa', {
                modulusLength: 1024,
                publicKeyEncoding: {
                    type: 'spki', format: 'pem'
                },
                privateKeyEncoding: {
                    type: 'pkcs8', format: 'pem'
                }
            });
        const public_key_enc = Encryption.changeAuthType(publicKey.toString('base64'));
        return {
            public_key_enc,
            private_key: privateKey
        };
    }
}
function getUrl(type) {
    if (type == "api") {
        return `https://messengerg2c${Math.floor(Math.random()*69)}.iranlms.ir/`
    }
}
function sendPost(data) {
    try {
        const header = {
            "Content-Type": "text/plain",
            "Accept": "application/json, text/plain, */*",
            "User-Agent": "Mozilla/5.0 (Linux; U; Android 12; en; M2004J19C Build/SP1A.210812.016) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/110.0.0.0 Mobile Safari/537.36",
            "Referer": "https://web.rubika.ir/"
        }
        const response = request("POST", getUrl("api"), {
            headers: header,
            json: data
        })
        return response.getBody().toString()
    }catch(e) {
        return "connection error"
    }
};
class jsrubi {
    constructor(auth, key) {
        this.auth = auth;
        try {
            key = JSON.parse(Buffer.from(key, 'base64').toString('utf-8'))['d'];
        } catch(e) {
            console.log("your key is not valid please check key")
        }
        this.enc = new Encryption(Encryption.changeAuthType(auth), key)
        this.client = {
            "app_name": "Main",
            "app_version": "4.3.5",
            "platform": "Web",
            "package": "web.rubika.ir",
            "lang_code": "fa"
        }
        this.msgInfo = null

    }
    errorHandler(inData) {
        let encode = this.enc.encrypt(JSON.stringify(inData))
        let signData = this.enc.makeSignFromData(encode)
        let enc_data = {
            "api_version": "6",
            "auth": this.auth,
            "data_enc": encode,
            "sign": signData
        }
        let getResponse = sendPost(enc_data)
        while (true) {
            if (getResponse == "connection error") {
                getResponse = sendPost(enc_data)
            } else {
                let resultData = JSON.parse(this.enc.decrypt(JSON.parse(getResponse).data_enc))

                return resultData
                break;
            }
        }
    }
    updateHandler(updates) {
        if (updates.length > 0) {
            if (this.msgInfo != updates[0].last_message.message_id) {
                this.msgInfo = updates[0].last_message.message_id
                return updates[0]
            }
        }
    }
    getChatsUpdates() {
        let date = new Date().getTime()+""
        let dateArray = []
        for (let num in date) {
            dateArray.push(date[num])
        }
        let statenum = parseInt(dateArray.slice(0, 10).join('')) - 200
        let inData = {
            "method": "getChatsUpdates",
            "input": {
                "state": statenum
            },
            "client": this.client
        }
        let response = this.errorHandler(inData).data.chats
        return this.updateHandler(response)
    }
    getUserInfoById(username) {
        username = username.split("@")
        username = username[username.length-1]
        let getGuid = this.getObjectByUsername(username).data.user.user_guid
        let inData = {
            "method": "getUserInfo",
            "input": {
                "user_guid": getGuid
            },
            "client": this.client
        }
        return this.errorHandler(inData)
    }
    getUserInfo(user_guid) {
        let inData = {
            "method": "getUserInfo",
            "input": {
                "user_guid": user_guid
            },
            "client": this.client
        }
        return this.errorHandler(inData)
    }
    getChannelInfo(channel_guid) {
        let inData = {
            "method": "getChannelInfo",
            "input": {
                "channel_guid": channel_guid
            },
            "client": this.client
        }
        return this.errorHandler(inData)
    }
    getChannelInfoByLink(link) {
        link = link.split("/")
        link = link[link.length-1]
        let cGuid = this.channelPreviewByJoinLink(link).data.channel.channel_guid
        let inData = {
            "method": "getChannelInfo",
            "input": {
                "channel_guid": cGuid
            },
            "client": this.client
        }
        return this.errorHandler(inData)
    }
    getChannelInfoById(username) {
        let getGuid;
        if (username.includes("https://") || username.includes("http://")) {
            getGuid = this.getLinkFromAppUrl(username).data.link.open_chat_data.object_guid
        } else {
            username = username.split("@")
            username = username[username.length-1]
            getGuid = this.getObjectByUsername(username).data.channel.channel_guid
        }
        let inData = {
            "method": "getChannelInfo",
            "input": {
                "channel_guid": getGuid
            },
            "client": this.client
        }
        return this.errorHandler(inData)
    }
    getGroupInfo(group_guid) {
        let inData = {
            "method": "getGroupInfo",
            "input": {
                "group_guid": group_guid
            },
            "client": this.client
        }
        return this.errorHandler(inData)
    }
    getGroupInfoByLink(link) {
        let guidGroup = this.groupPreviewByJoinLink(link).data.group.group_guid
        let inData = {
            "method": "getGroupInfo",
            "input": {
                "group_guid": guidGroup
            },
            "client": this.client
        }
        return this.errorHandler(inData)
    }
    getBlockedUsers() {
        let inData = {
            "method": "getBlockedUsers",
            "input": {
                "start_id": null
            },
            "client": this.client
        }
        return this.errorHandler(inData)
    }
    getMySessions() {
        let inData = {
            "method": "getMySessions",
            "input": {},
            "client": this.client
        }
        return this.errorHandler(inData)
    }
    getLinkFromAppUrl(app_url) {
        let inData = {
            "method": "getLinkFromAppUrl",
            "input": {
                "app_url": app_url
            },
            "client": this.client
        }
        return this.errorHandler(inData)
    }
    sendMessage(chat_id, text, message_id) {
        let inData = {
            "method": "sendMessage",
            "input": {
                "object_guid": chat_id,
                "rnd": Math.floor(Math.random()*999999999),
                "file_inline": null,
                "text": text,
                ...(message_id && {
                    "reply_to_message_id": message_id
                })
            },
            "client": this.client

        }
        return this.errorHandler(inData)
    }
    deleteMessages(chat_id, message_ids) {
        let inData = {
            "method": "deleteMessages",
            "input": {
                "object_guid": chat_id,
                "message_ids": message_ids,
                "type": "Global"
            },
            "client": this.client

        }
        return this.errorHandler(inData)
    }
    forwardMessages(from, to, message_ids) {
        let inData = {
            "method": "forwardMessages",
            "input": {
                "from_object_guid": from,
                "to_object_guid": to,
                "message_ids": message_ids,
                "rnd": Math.floor(Math.random()*999999999)},
            "client": this.client
        }
        return this.errorHandler(inData)
    }
    joinGroup(link) {
        if (link) {
            link = link.split("/")
            link = link[link.length-1]
            let inData = {
                "method": "joinGroup",
                "input": {
                    "hash_link": link
                },
                "client": this.client
            }
            return this.errorHandler(inData)
        }
    }
    leaveGroup(group_guid) {
        let inData = {
            "method": "leaveGroup",
            "input": {
                "group_guid": group_guid
            },
            "client": this.client
        }
        return this.errorHandler(inData)
    }
    groupPreviewByJoinLink(link) {
        link = link.split("/")
        link = link[link.length-1]
        let inData = {
            "method": "groupPreviewByJoinLink",
            "input": {
                "hash_link": link
            },
            "client": this.client
        }
        return this.errorHandler(inData)
    }
    leaveGroupByLink(link) {
        let guidGroup = this.groupPreviewByJoinLink(link).data.group.group_guid
        let inData = {
            "method": "leaveGroup",
            "input": {
                "group_guid": guidGroup
            },
            "client": this.client
        }
        return this.errorHandler(inData)
    }
    joinChannelByLink(link) {
        link = link.split("/")
        link = link[link.length-1]
        let inData = {
            "method": "joinChannelByLink",
            "input": {
                "hash_link": link
            },
            "client": this.client
        }
        return this.errorHandler(inData)
    }
    joinChannelAction(channel_guid, action) {
        let inData = {
            "method": "joinChannelAction",
            "input": {
                "channel_guid": channel_guid,
                "action": action
            },
            "client": this.client
        }
        return this.errorHandler(inData)
    }
    joinChannelActionById(
        username, action) {
        let getGuid;
        if (username.includes("https://") || username.includes("http://")) {
            getGuid = this.getLinkFromAppUrl(username).data.link.open_chat_data.object_guid
        } else {
            username = username.split("@")
            username = username[username.length-1]
            getGuid = this.getObjectByUsername(username).data.channel.channel_guid
        }
        let inData = {
            "method": "joinChannelAction",
            "input": {
                "channel_guid": getGuid,
                "action": action
            },
            "client": this.client
        }
        return this.errorHandler(inData)
    }
    leaveChannel(channel_guid) {
        let inData = {
            "method": "joinChannelAction",
            "input": {
                "channel_guid": channel_guid,
                "action": "Leave"
            },
            "client": this.client
        }
        return this.errorHandler(inData)
    }
    leaveChannelByLink(link) {
        link = link.split("/")
        link = link[link.length-1]
        let cGuid = this.channelPreviewByJoinLink(link).data.channel.channel_guid
        let inData = {
            "method": "joinChannelAction",
            "input": {
                "channel_guid": cGuid,
                "action": "Leave"
            },
            "client": this.client
        }
        return this.errorHandler(inData)
    }
    leaveChannelById(username) {
        let getGuid;
        if (username.includes("https://") || username.includes("http://")) {
            getGuid = this.getLinkFromAppUrl(username).data.link.open_chat_data.object_guid
        } else {
            username = username.split("@")
            username = username[username.length-1]
            getGuid = this.getObjectByUsername(username).data.channel.channel_guid
        }
        let inData = {
            "method": "joinChannelAction",
            "input": {
                "channel_guid": getGuid,
                "action": "Leave"
            },
            "client": this.client
        }
        return this.errorHandler(inData)
    }
    channelPreviewByJoinLink(link) {
        link = link.split("/")
        link = link[link.length-1]
        let inData = {
            "method": "joinChannelByLink",
            "input": {
                "hash_link": link
            },
            "client": this.client
        }
        return this.errorHandler(inData)
    }
    joinChannelById(username) {
        let getGuid;
        if (username.includes("https://") || username.includes("http://")) {
            getGuid = this.getLinkFromAppUrl(username).data.link.open_chat_data.object_guid
        } else {
            username = username.split("@")
            username = username[username.length-1]
            getGuid = this.getObjectByUsername(username).data.channel.channel_guid
        }
        let inData = {
            "method": "joinChannelAction",
            "input": {
                "channel_guid": getGuid,
                "action": "Join"
            },
            "client": this.client
        }
        return this.errorHandler(inData)
    }
    getObjectByUsername(username) {
        let inData = {
            "method": "getObjectByUsername",
            "input": {
                "username": username
            },
            "client": this.client
        }
        return this.errorHandler(inData)
    }
}
module.exports = jsrubi