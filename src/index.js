require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const moment = require('moment');
const qs = require('qs');
const xmlrpc = require('xmlrpc');

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// --- CẤU HÌNH BIẾN MÔI TRƯỜNG ---
const {
    ODOO_URL,
    ODOO_DB,
    ODOO_USER,
    ODOO_PASSWORD,
    VNP_TMN_CODE,
    VNP_HASH_SECRET,
    VNP_URL,
    VNP_RETURN_URL
} = process.env;

// --- HÀM HỖ TRỢ: Sắp xếp tham số VNPay ---
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

// --- HÀM HỖ TRỢ: Gọi Odoo qua XML-RPC ---
function callOdoo(model, method, args) {
    const common = xmlrpc.createSecureClient(`${ODOO_URL}/xmlrpc/2/common`);
    return new Promise((resolve, reject) => {
        common.methodCall('authenticate', [ODOO_DB, ODOO_USER, ODOO_PASSWORD, {}], (err, uid) => {
            if (err || !uid) return reject(err || "Auth failed");
            const models = xmlrpc.createSecureClient(`${ODOO_URL}/xmlrpc/2/object`);
            models.methodCall('execute_kw', [ODOO_DB, uid, ODOO_PASSWORD, model, method, args], (err, res) => {
                if (err) return reject(err);
                resolve(res);
            });
        });
    });
}

// 1. API: NHẬN WEBHOOK TỪ ODOO -> TẠO LINK VNPAY
app.post('/webhook/odoo-to-vnpay', async(req, res) => {
    try {
        const { id, amount_total, name } = req.body;
        if (!id) return res.status(400).send("Missing ID");

        let date = new Date();
        let createDate = moment(date).format('YYYYMMDDHHmmss');
        let amount = Math.round(amount_total * 100); // VNPay yêu cầu x100

        let vnp_Params = {
            'vnp_Version': '2.1.0',
            'vnp_Command': 'pay',
            'vnp_TmnCode': VNP_TMN_CODE,
            'vnp_Locale': 'vn',
            'vnp_CurrCode': 'VND',
            'vnp_TxnRef': `${id}_${createDate}`, // ID hóa đơn + timestamp
            'vnp_OrderInfo': `Thanh toan hoa don ${name}`,
            'vnp_OrderType': 'billpayment',
            'vnp_Amount': amount,
            'vnp_ReturnUrl': VNP_RETURN_URL,
            'vnp_IpAddr': req.headers['x-forwarded-for'] || req.socket.remoteAddress,
            'vnp_CreateDate': createDate
        };

        vnp_Params = sortObject(vnp_Params);
        let signData = qs.stringify(vnp_Params, { encode: false });
        let hmac = crypto.createHmac("sha512", VNP_HASH_SECRET);
        let signed = hmac.update(Buffer.from(signData, 'utf-8')).digest("hex");
        vnp_Params['vnp_SecureHash'] = signed;

        const paymentUrl = VNP_URL + '?' + qs.stringify(vnp_Params, { encode: false });

        // Ghi ngược link vào Odoo (trường x_vnpay_url)
        // Ghi link vào phần Thảo luận (Chatter) thay vì tạo trường mới
        await callOdoo('mail.message', 'create', [{
            'model': 'account.move',
            'res_id': id,
            'body': `Link thanh toán VNPay đã được tạo: <a href="${paymentUrl}" target="_blank">Bấm vào đây để thanh toán</a>`,
            'message_type': 'comment',
            'subtype_id': 1 // ID của kiểu thảo luận công khai
        }]);

        res.json({ status: 'success', url: paymentUrl });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: error.message });
    }
});

// 2. API: NHẬN IPN TỪ VNPAY (XÁC NHẬN THANH TOÁN)
app.get('/webhook/vnpay-ipn', async(req, res) => {
    let vnp_Params = req.query;
    let secureHash = vnp_Params['vnp_SecureHash'];

    delete vnp_Params['vnp_SecureHash'];
    delete vnp_Params['vnp_SecureHashType'];

    vnp_Params = sortObject(vnp_Params);
    let signData = qs.stringify(vnp_Params, { encode: false });
    let hmac = crypto.createHmac("sha512", VNP_HASH_SECRET);
    let signed = hmac.update(Buffer.from(signData, 'utf-8')).digest("hex");

    if (secureHash === signed) {
        let orderId = vnp_Params['vnp_TxnRef'].split('_')[0];
        let responseCode = vnp_Params['vnp_ResponseCode'];

        if (responseCode === '00') {
            // Thanh toán thành công -> Ghi log vào Odoo Chatter
            await callOdoo('mail.message', 'create', [{
                'model': 'account.move',
                'res_id': parseInt(orderId),
                'body': `Thanh toán VNPay thành công. Mã GD: ${vnp_Params['vnp_TransactionNo']}`,
                'message_type': 'notification'
            }]);
            res.status(200).json({ RspCode: '00', Message: 'Success' });
        } else {
            res.status(200).json({ RspCode: '01', Message: 'Fail' });
        }
    } else {
        res.status(200).json({ RspCode: '97', Message: 'Invalid Checksum' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));