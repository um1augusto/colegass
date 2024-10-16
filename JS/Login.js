document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    const response = await fetch('http://localhost:3000/Login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
    });

    const messageElement = document.getElementById('message');
    if (response.ok) {
        // Redireciona para a página do usuário passando o email na query string
        window.location.href = 'PaginaDoUsuario.html?email=' + encodeURIComponent(email);
    } else {
        const errorMessage = await response.text();
        messageElement.textContent = errorMessage;
    }
});
