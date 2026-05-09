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

// --- LẤY BIẾN MÔI TRƯỜNG TỪ RAILWAY ---
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

// --- HÀM SORT CHÍNH CHỦ VNPAY ---
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
// 1. API: ODOO GỌI SANG ĐỂ TẠO LINK THANH TOÁN
// =====================================================================
app.post('/webhook/odoo-to-vnpay', async(req, res) => {
    try {
        console.log("=== NHẬN DỮ LIỆU TỪ ODOO ===", req.body);

        const id = req.body.id || req.body._id;
        const amount_total = req.body.amount_residual || req.body.amount_total;
        const name = req.body.display_name || req.body.name || id;

        let date = new Date();
        let createDate = moment(date).format('YYYYMMDDHHmmss');

        let ipAddr = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

        let vnp_Params = {};
        vnp_Params['vnp_Version'] = '2.1.0';
        vnp_Params['vnp_Command'] = 'pay';
        vnp_Params['vnp_TmnCode'] = VNP_TMN_CODE;
        vnp_Params['vnp_Locale'] = 'vn';
        vnp_Params['vnp_CurrCode'] = 'VND';
        vnp_Params['vnp_TxnRef'] = `${id}_${createDate}`; // Gắn ID Odoo vào Ref
        vnp_Params['vnp_OrderInfo'] = 'Thanh toan cho hoa don: ' + name;
        vnp_Params['vnp_OrderType'] = 'other';
        vnp_Params['vnp_Amount'] = Math.round(amount_total * 100);
        vnp_Params['vnp_ReturnUrl'] = VNP_RETURN_URL;
        vnp_Params['vnp_IpAddr'] = ipAddr;
        vnp_Params['vnp_CreateDate'] = createDate;

        vnp_Params = sortObject(vnp_Params);

        let signData = qs.stringify(vnp_Params, { encode: false });
        let hmac = crypto.createHmac("sha512", VNP_HASH_SECRET);
        let signed = hmac.update(Buffer.from(signData, 'utf-8')).digest("hex");

        vnp_Params['vnp_SecureHash'] = signed;
        const paymentUrl = VNP_URL + '?' + qs.stringify(vnp_Params, { encode: false });

        // Gửi link về Odoo Chatter
        await callOdoo('mail.message', 'create', [{
            'model': 'account.move',
            'res_id': parseInt(id),
            'body': `Link thanh toán VNPay đã được tạo: <a href="${paymentUrl}" target="_blank">Bấm vào đây để thanh toán</a>`,
            'message_type': 'comment',
            'subtype_id': 1
        }]);

        res.json({ status: 'success', url: paymentUrl });
    } catch (error) {
        console.error(error);
        res.status(500).send(error.message);
    }
});

// =====================================================================
// 2. API: VNPAY GỌI VỀ ĐỂ XÁC NHẬN (IPN & RETURN)
// =====================================================================
// Thay thư viện 'qs' bằng 'querystring' mặc định của Node để giống 100% VNPay
const querystring = require('querystring');

app.get('/webhook/vnpay-ipn', async(req, res) => {
    try {
        let vnp_Params = req.query;
        let secureHash = vnp_Params['vnp_SecureHash'];

        delete vnp_Params['vnp_SecureHash'];
        delete vnp_Params['vnp_SecureHashType'];

        vnp_Params = sortObject(vnp_Params);

        // Dùng thư viện qs với encode: false để tránh bị lỗi [object Object]
        let signData = qs.stringify(vnp_Params, { encode: false });

        const secretKey = process.env.VNP_HASH_SECRET.trim();
        let hmac = crypto.createHmac("sha512", secretKey);
        let signed = hmac.update(Buffer.from(signData, 'utf-8')).digest("hex");
        // ==========================================
        // KHU VỰC ĐÈN PHA SO CHIẾU LỖI (HIỆN TRONG LOG)
        // ==========================================
        console.log("\n====== BẮT ĐẦU DEBUG CHECKSUM ======");
        console.log("1. Chiều dài Secret Key hiện tại:", secretKey.length, "(Chuẩn của VNPay phải là 32 ký tự)");
        console.log("2. Chuỗi dữ liệu mang đi băm (signData): \n" + signData);
        console.log("3. Hash của VNPay mang tới :", secureHash);
        console.log("4. Hash do Server tính ra  :", signed);
        console.log("======================================\n");

        if (secureHash === signed) {
            let responseCode = vnp_Params['vnp_ResponseCode'];
            let txnRef = vnp_Params['vnp_TxnRef'];
            let orderId = txnRef.split('_')[0];

            if (responseCode === '00') {
                await callOdoo('mail.message', 'create', [{
                    'model': 'account.move',
                    'res_id': parseInt(orderId),
                    'body': `✅ <b>Thanh toán thành công qua VNPay.</b><br/>Mã giao dịch: ${vnp_Params['vnp_TransactionNo']}`,
                    'message_type': 'notification'
                }]);
                return res.status(200).json({ RspCode: '00', Message: 'Success' });
            } else {
                return res.status(200).json({ RspCode: '01', Message: 'Fail' });
            }
        } else {
            return res.status(200).json({ RspCode: '97', Message: 'Invalid Checksum' });
        }
    } catch (error) {
        console.error("LỖI IPN:", error);
        return res.status(500).json({ RspCode: '99', Message: 'Internal Error' });
    }
});
// =====================================================================
// 3. API: HIỂN THỊ GIAO DIỆN TRÌNH DUYỆT (RETURN URL)
// =====================================================================
// =====================================================================
// 3. API: HIỂN THỊ GIAO DIỆN TRÌNH DUYỆT (RETURN URL)
// =====================================================================
app.get('/webhook/vnpay-return', (req, res) => {
            try {
                let vnp_Params = req.query;
                let secureHash = vnp_Params['vnp_SecureHash'];

                delete vnp_Params['vnp_SecureHash'];
                delete vnp_Params['vnp_SecureHashType'];

                vnp_Params = sortObject(vnp_Params);

                // Dùng thư viện qs với encode: false để tránh bị lỗi [object Object]
                let signData = qs.stringify(vnp_Params, { encode: false });

                const secretKey = process.env.VNP_HASH_SECRET.trim();
                let hmac = crypto.createHmac("sha512", secretKey);
                let signed = hmac.update(Buffer.from(signData, 'utf-8')).digest("hex");

                // === BẬT ĐÈN PHA SOI LỖI LUỒNG RETURN ===
                console.log("\n====== DEBUG GIAO DIỆN RETURN ======");
                console.log("1. Dữ liệu trình duyệt mang đi băm (signData): \n" + signData);
                console.log("2. Hash VNPay gửi về :", secureHash);
                console.log("3. Hash Server tính  :", signed);
                console.log("====================================\n");

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
                res.send(renderHTML(true, "Thanh toán thành công!", "Cảm ơn bạn đã thanh toán. Hóa đơn trên hệ thống đã được cập nhật.", "#10b981", "✓"));
            } else {
                res.send(renderHTML(false, "Thanh toán thất bại!", "Giao dịch không thành công hoặc đã bị hủy.", "#ef4444", "✗"));
            }
        } else {
            res.send(renderHTML(false, "Lỗi xác thực!", "Dữ liệu không hợp lệ. Vui lòng liên hệ bộ phận hỗ trợ.", "#f59e0b", "⚠"));
        }
    } catch (e) {
        res.send("Có lỗi xảy ra trong quá trình xử lý giao diện.");
    }
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server Railway chạy tại port ${PORT}`));