require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const moment = require('moment');
const qs = require('qs'); // Đảm bảo dùng 'qs' thay vì 'querystring' mặc định
const xmlrpc = require('xmlrpc');

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// --- HÀM SORT CHÍNH CHỦ VNPAY (Đã fix lỗi dấu cách) ---
function sortObject(obj) {
    let sorted = {};
    let str = [];
    let key;
    for (key in obj) {
        if (obj.hasOwnProperty(key)) {
            str.push(encodeURIComponent(key));
        }
    }
    str.sort();
    for (key = 0; key < str.length; key++) {
        sorted[str[key]] = encodeURIComponent(obj[str[key]]).replace(/%20/g, "+");
    }
    return sorted;
}

// --- API TẠO LINK (Đã khớp với code bạn gửi) ---
app.post('/webhook/odoo-to-vnpay', async(req, res) => {
    try {
        const secretKey = process.env.VNP_HASH_SECRET;
        let vnpUrl = process.env.VNP_URL;

        const id = req.body.id || req.body._id;
        const amount_total = req.body.amount_residual || req.body.amount_total;
        const name = req.body.display_name || req.body.name || `Hóa đơn ${id}`;

        let date = new Date();
        let createDate = moment(date).format('YYYYMMDDHHmmss');
        let amount = Math.round(amount_total * 100);

        let vnp_Params = {
            'vnp_Version': '2.1.0',
            'vnp_Command': 'pay',
            'vnp_TmnCode': process.env.VNP_TMN_CODE,
            'vnp_Locale': 'vn',
            'vnp_CurrCode': 'VND',
            'vnp_TxnRef': `${id}_${createDate}`,
            'vnp_OrderInfo': `Thanh toan hoa don ${name}`,
            'vnp_OrderType': 'billpayment',
            'vnp_Amount': amount,
            'vnp_ReturnUrl': process.env.VNP_RETURN_URL,
            'vnp_IpAddr': req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1',
            'vnp_CreateDate': createDate
        };

        vnp_Params = sortObject(vnp_Params);
        let signData = qs.stringify(vnp_Params, { encode: false });
        let hmac = crypto.createHmac("sha512", secretKey);
        let signed = hmac.update(Buffer.from(signData, 'utf-8')).digest("hex");

        vnp_Params['vnp_SecureHash'] = signed;
        vnpUrl += '?' + qs.stringify(vnp_Params, { encode: false });

        // Gọi Odoo để ghi nhận link (Dùng hàm callOdoo của chúng ta)
        await callOdoo('mail.message', 'create', [{
            'model': 'account.move',
            'res_id': parseInt(id),
            'body': `Link thanh toán VNPay: <a href="${vnpUrl}" target="_blank">Thanh toán ngay</a>`,
            'message_type': 'comment',
            'subtype_id': 1
        }]);

        res.json({ status: 'success', url: vnpUrl });
    } catch (e) {
        res.status(500).send(e.message);
    }
});

// --- API IPN (Cần dùng cùng logic băm để không bị lỗi 97) ---
app.get('/webhook/vnpay-ipn', async(req, res) => {
    let vnp_Params = req.query;
    let secureHash = vnp_Params['vnp_SecureHash'];

    delete vnp_Params['vnp_SecureHash'];
    delete vnp_Params['vnp_SecureHashType'];

    vnp_Params = sortObject(vnp_Params);

    let signData = qs.stringify(vnp_Params, { encode: false });
    let hmac = crypto.createHmac("sha512", process.env.VNP_HASH_SECRET);
    let signed = hmac.update(Buffer.from(signData, 'utf-8')).digest("hex");

    if (secureHash === signed) {
        let orderId = vnp_Params['vnp_TxnRef'].split('_')[0];
        if (vnp_Params['vnp_ResponseCode'] === '00') {
            await callOdoo('mail.message', 'create', [{
                'model': 'account.move',
                'res_id': parseInt(orderId),
                'body': `✅ Thanh toán VNPay thành công. GD: ${vnp_Params['vnp_TransactionNo']}`,
                'message_type': 'notification'
            }]);
            return res.json({ RspCode: '00', Message: 'Success' });
        }
        return res.json({ RspCode: '01', Message: 'Fail' });
    } else {
        console.log("Checksum Fail! Check SecretKey or Sort logic.");
        return res.json({ RspCode: '97', Message: 'Invalid Checksum' });
    }
});

// Hàm callOdoo (Giữ nguyên như bản trước)
async function callOdoo(model, method, args) {
    const { ODOO_URL, ODOO_DB, ODOO_USER, ODOO_PASSWORD } = process.env;
    const isHttps = ODOO_URL.startsWith('https');
    const clientCreator = isHttps ? xmlrpc.createSecureClient : xmlrpc.createClient;
    const client = clientCreator(`${ODOO_URL}/xmlrpc/2/object`);
    const common = clientCreator(`${ODOO_URL}/xmlrpc/2/common`);

    return new Promise((resolve, reject) => {
        common.methodCall('authenticate', [ODOO_DB, ODOO_USER, ODOO_PASSWORD, {}], (err, uid) => {
            if (err || !uid) return reject(err || "Auth failed");
            client.methodCall('execute_kw', [ODOO_DB, uid, ODOO_PASSWORD, model, method, args], (err, res) => {
                if (err) return reject(err);
                resolve(res);
            });
        });
    });
}

app.listen(process.env.PORT || 3000);