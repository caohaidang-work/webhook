require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const moment = require('moment');
const qs = require('qs'); // Dùng đúng thư viện qs của VNPay
const xmlrpc = require('xmlrpc');

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// --- HÀM SORT NGUYÊN BẢN CỦA VNPAY (GIỮ NGUYÊN 100%) ---
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

// --- HÀM GỌI ODOO ---
function callOdoo(model, method, args) {
    const { ODOO_URL, ODOO_DB, ODOO_USER, ODOO_PASSWORD } = process.env;
    const isHttps = ODOO_URL.startsWith('https');
    const clientCreator = isHttps ? xmlrpc.createSecureClient : xmlrpc.createClient;
    const client = clientCreator(`${ODOO_URL}/xmlrpc/2/object`);
    const common = clientCreator(`${ODOO_URL}/xmlrpc/2/common`);

    return new Promise((resolve, reject) => {
        common.methodCall('authenticate', [ODOO_DB, ODOO_USER, ODOO_PASSWORD, {}], (err, uid) => {
            if (err || !uid) return reject(err || "Auth failed Odoo");
            client.methodCall('execute_kw', [ODOO_DB, uid, ODOO_PASSWORD, model, method, args], (err, res) => {
                if (err) return reject(err);
                resolve(res);
            });
        });
    });
}

// =====================================================================
// 1. API: TẠO LINK THANH TOÁN (LUỒNG ĐI)
// =====================================================================
app.post('/webhook/odoo-to-vnpay', async(req, res) => {
    try {
        const id = req.body.id || req.body._id;
        const amount_total = req.body.amount_residual || req.body.amount_total;

        // BỘ LỌC AN TOÀN: Xóa ngoặc đơn, dấu xuyệt, dấu hai chấm... để tránh lệch Checksum lúc Return
        let rawName = req.body.display_name || req.body.name || `Hoa don ${id}`;
        let safeName = String(rawName).replace(/[^a-zA-Z0-9 ]/g, ' ');

        let date = new Date();
        let createDate = moment(date).format('YYYYMMDDHHmmss');

        let vnp_Params = {};
        vnp_Params['vnp_Version'] = '2.1.0';
        vnp_Params['vnp_Command'] = 'pay';
        vnp_Params['vnp_TmnCode'] = process.env.VNP_TMN_CODE;
        vnp_Params['vnp_Locale'] = 'vn';
        vnp_Params['vnp_CurrCode'] = 'VND';
        vnp_Params['vnp_TxnRef'] = `${id}_${createDate}`;
        vnp_Params['vnp_OrderInfo'] = 'Thanh toan HD ' + safeName;
        vnp_Params['vnp_OrderType'] = 'other';
        vnp_Params['vnp_Amount'] = Math.round(amount_total * 100);
        vnp_Params['vnp_ReturnUrl'] = process.env.VNP_RETURN_URL; // Đảm bảo Railway đang cấu hình đuôi /vnpay-return
        vnp_Params['vnp_IpAddr'] = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
        vnp_Params['vnp_CreateDate'] = createDate;

        // Băm theo đúng chuẩn VNPay
        vnp_Params = sortObject(vnp_Params);
        let signData = qs.stringify(vnp_Params, { encode: false });
        let hmac = crypto.createHmac("sha512", process.env.VNP_HASH_SECRET.trim());
        let signed = hmac.update(Buffer.from(signData, 'utf-8')).digest("hex");

        vnp_Params['vnp_SecureHash'] = signed;
        const paymentUrl = process.env.VNP_URL + '?' + qs.stringify(vnp_Params, { encode: false });

        // Gửi link về Odoo
        await callOdoo('mail.message', 'create', [{
            'model': 'account.move',
            'res_id': parseInt(id),
            'body': `Link thanh toán VNPay: <a href="${paymentUrl}" target="_blank">Thanh toán ngay</a>`,
            'message_type': 'comment',
            'subtype_id': 1
        }]);

        res.json({ status: 'success', url: paymentUrl });
    } catch (error) {
        res.status(500).send(error.message);
    }
});

// =====================================================================
// 2. API: NHẬN IPN TỪ VNPAY (LUỒNG CHẠY NGẦM BÁO VỀ ODOO)
// =====================================================================
app.get('/webhook/vnpay-ipn', async(req, res) => {
    try {
        let vnp_Params = req.query;
        let secureHash = vnp_Params['vnp_SecureHash'];

        delete vnp_Params['vnp_SecureHash'];
        delete vnp_Params['vnp_SecureHashType'];

        // Logic băm chuẩn VNPay
        vnp_Params = sortObject(vnp_Params);
        let signData = qs.stringify(vnp_Params, { encode: false });
        let hmac = crypto.createHmac("sha512", process.env.VNP_HASH_SECRET.trim());
        let signed = hmac.update(Buffer.from(signData, 'utf-8')).digest("hex");

        if (secureHash === signed) {
            let orderId = vnp_Params['vnp_TxnRef'].split('_')[0];
            if (vnp_Params['vnp_ResponseCode'] === '00') {
                await callOdoo('mail.message', 'create', [{
                    'model': 'account.move',
                    'res_id': parseInt(orderId),
                    'body': `✅ <b>Thanh toán thành công qua VNPay.</b><br/>Mã GD: ${vnp_Params['vnp_TransactionNo']}`,
                    'message_type': 'notification'
                }]);
                return res.status(200).json({ RspCode: '00', Message: 'Success' });
            }
            return res.status(200).json({ RspCode: '01', Message: 'Fail' });
        } else {
            return res.status(200).json({ RspCode: '97', Message: 'Invalid Checksum' });
        }
    } catch (e) {
        return res.status(500).json({ RspCode: '99', Message: 'Error' });
    }
});

// =====================================================================
// 3. API: HIỂN THỊ GIAO DIỆN TRÌNH DUYỆT (LUỒNG RETURN CHO KHÁCH)
// =====================================================================
app.get('/webhook/vnpay-return', (req, res) => {
            let vnp_Params = req.query;
            let secureHash = vnp_Params['vnp_SecureHash'];

            delete vnp_Params['vnp_SecureHash'];
            delete vnp_Params['vnp_SecureHashType'];

            // Logic băm chuẩn VNPay giống hệt IPN
            vnp_Params = sortObject(vnp_Params);
            let signData = qs.stringify(vnp_Params, { encode: false });
            let hmac = crypto.createHmac("sha512", process.env.VNP_HASH_SECRET.trim());
            let signed = hmac.update(Buffer.from(signData, 'utf-8')).digest("hex");

            // Giao diện HTML
            const renderHTML = (isSuccess, title, message, color, icon) => `
    <!DOCTYPE html>
    <html lang="vi">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Kết quả thanh toán</title>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f3f4f6; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
            .card { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 10px 15px -3px rgba(0,0,0,0.1); text-align: center; max-width: 400px; width: 90%; }
            .icon { font-size: 60px; color: ${color}; margin-bottom: 20px; }
            .title { color: #1f2937; font-size: 24px; font-weight: bold; margin-bottom: 10px; }
            .message { color: #6b7280; font-size: 16px; margin-bottom: 30px; line-height: 1.5; }
            .details { background: #f9fafb; padding: 15px; border-radius: 8px; text-align: left; margin-bottom: 30px; font-size: 14px; color: #4b5563;}
            .details div { padding: 5px 0; border-bottom: 1px dashed #e5e7eb; }
            .details div:last-child { border-bottom: none; }
            .btn { background-color: ${color}; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold; transition: opacity 0.2s; display: inline-block;}
            .btn:hover { opacity: 0.9; }
        </style>
    </head>
    <body>
        <div class="card">
            <div class="icon">${icon}</div>
            <div class="title">${title}</div>
            <div class="message">${message}</div>
            ${isSuccess ? `
            <div class="details">
                <div><strong>Mã giao dịch:</strong> ${vnp_Params['vnp_TransactionNo']}</div>
                <div><strong>Số tiền:</strong> ${(vnp_Params['vnp_Amount']/100).toLocaleString('vi-VN')} VND</div>
                <div><strong>Ngân hàng:</strong> ${vnp_Params['vnp_BankCode']}</div>
            </div>` : ''}
            <a href="#" onclick="window.close()" class="btn">Đóng cửa sổ này</a>
        </div>
    </body>
    </html>`;

    if (secureHash === signed) {
        if (vnp_Params['vnp_ResponseCode'] === '00') {
            res.send(renderHTML(true, "Thanh toán thành công!", "Cảm ơn bạn đã thanh toán. Hóa đơn đã được cập nhật.", "#10b981", "✓"));
        } else {
            res.send(renderHTML(false, "Thanh toán thất bại!", "Giao dịch không thành công hoặc đã bị hủy.", "#ef4444", "✗"));
        }
    } else {
        res.send(renderHTML(false, "Lỗi xác thực!", "Dữ liệu không hợp lệ. Vui lòng liên hệ bộ phận hỗ trợ.", "#f59e0b", "⚠"));
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server Railway chạy tại port ${PORT}`));