async function appendLogEntry(actionDescription) {
    const logArea = document.getElementById('logArea');
    logArea.value += actionDescription + '\n\n';
    logArea.scrollTop = logArea.scrollHeight;
}

async function generateKeys() {
    appendLogEntry('Запрос: Генерация ключей...');
    const response = await fetch('/generate_keys', { method: 'POST' });
    const data = await response.json();
    appendLogEntry(`Ключи сгенерированы:\nПубличный ключ: ${JSON.stringify(data.public_key, null, 2)}\nПриватный ключ: ${JSON.stringify(data.private_key, null, 2)}`);
}

async function issueRootCert() {
    appendLogEntry('Запрос: Выпуск Root-сертификата...');
    const response = await fetch('/issue_root_cert', { method: 'POST' });
    const data = await response.json();
    appendLogEntry(`Root-сертификат:\nСубъект: ${data.subject}\nПубличный ключ: ${JSON.stringify(data.public_key, null, 2)}\nВременная метка: ${data.timestamp}\nПодпись:\n  r: ${data.signature.r}\n  s: ${data.signature.s}`);
}

async function fetchRootCert() {
    appendLogEntry('Запрос: Получение Root-сертификата...');
    const response = await fetch('/send_root_cert');
    const data = await response.json();
    appendLogEntry(`Получен Root-сертификат:\nСубъект: ${data.subject}\nПубличный ключ: ${JSON.stringify(data.public_key, null, 2)}\nВременная метка: ${data.timestamp}\nПодпись:\n  r: ${data.signature.r}\n  s: ${data.signature.s}`);
}