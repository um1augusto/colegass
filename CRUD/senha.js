const bscrypt = require('bcrypt');

const password = 'sua_senha_aqui';
const saltRounds = 10;

bscrypt.hash(password, saltRounds, (err, hash) => {
    if (err) throw err;
    console.log(`Senha encriptada: ${hash}`)
});