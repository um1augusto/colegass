document.addEventListener('DOMContentLoaded', async () => {
    const params = new URLSearchParams(window.location.search);
    const email = params.get('email');

    const response = await fetch(`http://localhost:3000/PaginaDoUsuario?email=${encodeURIComponent(email)}`);
    const userInfoElement = document.getElementById('userInfo');

    if (response.ok) {
        const user = await response.json();
        userInfoElement.innerHTML = `
            <p>ID: ${user.id}</p>
            <p>Nome: ${user.nome}</p>
            <p>Email: ${user.email}</p>
        `;
    } else {
        userInfoElement.textContent = 'Erro ao carregar informações do usuário.';
    }

    document.getElementById('logout').addEventListener('click', () => {
        window.location.href = 'Login.html';
    });
});
