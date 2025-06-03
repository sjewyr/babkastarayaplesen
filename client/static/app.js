function appendLogEntry(actionDescription) {
    const logArea = document.getElementById('logArea');
    const timestamp = new Date().toLocaleTimeString();
    logArea.value += `[${timestamp}] ${actionDescription}\n\n`;
    logArea.scrollTop = logArea.scrollHeight;
}

function handleError(error, action) {
    console.error(`${action} error:`, error);
    appendLogEntry(`Ошибка при ${action}: ${error.message}`);
    return { status: 'error', message: error.message };
}

async function generateKeysAndCert() {
    appendLogEntry('Запрос: Получение сертификата и ключей клиента...');
    try {
        const response = await fetch('/certs/generate_keys_and_cert', { 
            method: 'POST' 
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const data = await response.json();
        
        if (data.status === 'success') {
            appendLogEntry(`Сертификат и ключи успешно получены:\n${JSON.stringify(data.data, null, 2)}\n\n${data.message}`);
        } else {
            appendLogEntry(`Ошибка: ${data.message}`);
        }
        return data;
    } catch (error) {
        return handleError(error, 'получении сертификата и ключей');
    }
}

async function getAllCerts() {
    appendLogEntry('Запрос: Получение сертификатов CA (Root и Intermediate)...');
    try {
        const response = await fetch('/certs/all_certs', { 
            method: 'GET' 
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const data = await response.json();
        
        if (data.status === 'success') {
            appendLogEntry(`Сертификаты CA успешно получены:\n${JSON.stringify(data.certs, null, 2)}\n\n${data.message}`);
        } else {
            appendLogEntry(`Ошибка: ${data.message}`);
        }
        return data;
    } catch (error) {
        return handleError(error, 'получении сертификатов CA');
    }
}

document.addEventListener('DOMContentLoaded', () => {
    console.log('Client certificate dashboard initialized');
});

async function sendMessage() {
    const clientId = document.getElementById('clientId').value;
    const message = document.getElementById('messageInput').value;
    const override_r = document.getElementById('override_r').value.trim();
    const override_s = document.getElementById('override_s').value.trim();



    if (!clientId || !message) {
        appendLogEntry('Ошибка: Укажите Client ID и сообщение');
        return { status: 'error', message: 'Укажите Client ID и сообщение' };
    }

    appendLogEntry(`Запрос: Отправка сообщения клиенту ${clientId}: "${message}"...`);
    try {
        let url = `/message/send_message?client_id=${encodeURIComponent(clientId)}&msg=${encodeURIComponent(message)}`;
        if (override_r) url += `&override_r=${encodeURIComponent(override_r)}`;
        if (override_s) url += `&override_s=${encodeURIComponent(override_s)}`;
        const response = await fetch(url, {
            method: 'POST'
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();

        
        appendLogEntry(`Сообщение успешно отправлено:\n${JSON.stringify(data, null, 2)}`);

        return data;
    } catch (error) {
        return handleError(error, 'отправке сообщения');
    }
}

async function getMessage() {
    appendLogEntry('Запрос: Получение сообщения...');
    try {
        const response = await fetch('/message/get_message', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({}) // Пустое тело, так как параметры передаются через сервер
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();

        
        appendLogEntry(`Сообщение успешно получено: "${data.message}"\nПроверка: ${data.check}`);
        return data;
    } catch (error) {
        return handleError(error, 'получении сообщения');
    }
}