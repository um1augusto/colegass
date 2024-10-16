const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const app = express();
app.use(bodyParser.json());
const bcrypt = require ('bcrypt');
const jwt = require ('jsonwebtoken');
const cors = require('cors');

const SECRET_KEY = 'seu_segredo_aqui;'

app.use(cors());

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'users'
});

const authenticateToken = (req, res, next) =>{
    const token = req.headers ['authorization'] && req.headers ['authorization'].split('')[1];

    if(!token) return res.sendStatus(401);

    jwt.verify(token, SECRET_KEY, (err, user) =>{
        if(err) return send.sendStatus(403);
        req.user = user;
        next();
    });
}

app.post('/Login', async (req, res) => {
    const { email, password } = req.body;
    
    db.query('SELECT * FROM users WHERE email = ? AND password = ?', [email, password], async (err, results) => {
        if (err) throw err;
        if (result.length === 0 || !(await bcrypt.compare(password, result[0].password))){
            return res.status(400).send('Email ou senha invalidos');
        }

        const token = jwt.sign ({email}, SECRET_KEY, {expiresIn: '1h'});
        res.json({token});
    });
});

app.post('/Registro', async(req, res) => {
    const { nome, email, password } = req.body;
    const hashedpassword = await bcrypt.hash(password, 10);

    db.query('SELECT email FROM users (nome, email, password) VALUES (?, ?, ?)', [email], (err, result) => {
        if (err) throw err;
        if (result.length > 0){
            return res.status(400).send('Usuario ja existe');
        }

    
    db.query('INSERT INTO users (nome, email, password) VALUES (?, ?, ?)', [nome, email, hashedpassword], (err, result) => {
        if (err) throw err;
        res.sendStatus(201); // Usuário registrado com sucesso
    });
});
});


app.get('/PaginaDoUsuario', (req, res) => {
    const email = req.query.email; // Vamos usar o email para buscar o usuário
    db.query('SELECT id, nome, email FROM users WHERE email = ?', [email], (err, results) => {
        if (err) throw err;
        if (results.length > 0) {
            res.json(results[0]); // Retorna os dados do usuário
        } else {
            res.status(404).send('Usuário não encontrado');
        }
    });
});

app.listen(3000, () => {
    console.log('Servidor rodando na porta 3000');
});