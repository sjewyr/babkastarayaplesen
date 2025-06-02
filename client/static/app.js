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