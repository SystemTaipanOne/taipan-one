const bcrypt = require('bcrypt');

// --- IMPORTANTE ---
// Escolha uma senha para o seu superadmin e coloque aqui.
const senhaParaConverter = 'maor123@';
// ------------------

const saltRounds = 10;

console.log(`Gerando hash para a senha: "${senhaParaConverter}"`);
console.log('Aguarde...');

bcrypt.hash(senhaParaConverter, saltRounds, function(err, hash) {
    if (err) {
        console.error('Ocorreu um erro ao gerar o hash:', err);
        return;
    }
    console.log('-------------------------------------------------------');
    console.log('SUCESSO! Seu hash foi gerado:');
    console.log(hash);
    console.log('-------------------------------------------------------');
    console.log('Copie a linha acima (que começa com $2b$10...) e use-a no comando UPDATE do MySQL.');
});