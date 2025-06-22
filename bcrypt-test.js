const bcrypt = require('bcrypt');

const senhaTeste = 'maor123@';
const hashCorreto = '$2b$10$1/hnhF1O8mESvS68pmBnnOrzlbbfWUvKOcxlSBmkX7yVspN.lx.qK';

bcrypt.compare(senhaTeste, hashCorreto, (err, result) => {
  if (err) {
    console.error('Erro no bcrypt:', err);
    return;
  }
  console.log('Senha bate com hash?', result);
});



