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

    if (!clientId || !message) {
        appendLogEntry('Ошибка: Укажите Client ID и сообщение');
        return { status: 'error', message: 'Укажите Client ID и сообщение' };
    }

    appendLogEntry(`Запрос: Отправка сообщения клиенту ${clientId}: "${message}"...`);
    try {
        const response = await fetch(`/message/send_message?client_id=${clientId}&msg=${encodeURIComponent(message)}`, {
            method: 'POST'
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();

        if (data.status === 'success') {
            appendLogEntry(`Сообщение успешно отправлено:\n${JSON.stringify(data, null, 2)}`);
        } else {
            appendLogEntry(`Ошибка: ${data.message}`);
        }
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

        if (data.check === 'Подпись верна') {
            appendLogEntry(`Сообщение успешно получено: "${data.message}"\nПроверка: ${data.check}`);
        } else {
            appendLogEntry(`Ошибка: ${data.check}`);
        }
        return data;
    } catch (error) {
        return handleError(error, 'получении сообщения');
    }
}