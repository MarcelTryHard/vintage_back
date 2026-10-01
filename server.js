const express = require('express');
const mysql = require('mysql2');
const path = require('path');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const port = 3000;

app.use(cors());
app.use(express.json());

const frontendPath = path.join(__dirname, '../Vintage_front');

app.use(express.static(frontendPath));

const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'trabalho_vintage'
});

const sessoes = new Map();

function criarToken() {
    return crypto.randomBytes(32).toString('hex');
}

function criarSenha(senha) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(senha, salt, 64).toString('hex');

    return `${salt}:${hash}`;
}

function verificarSenha(senha, senhaHash) {
    try {
        const partes = senhaHash.split(':');

        if (partes.length !== 2) {
            return false;
        }

        const salt = partes[0];
        const hash = partes[1];

        const novoHash = crypto.scryptSync(
            senha,
            salt,
            64
        ).toString('hex');

        return crypto.timingSafeEqual(
            Buffer.from(hash, 'hex'),
            Buffer.from(novoHash, 'hex')
        );
    } catch {
        return false;
    }
}

function autenticar(req, res, next) {
    const autorizacao = req.headers.authorization;

    if (!autorizacao) {
        return res.status(401).json({
            erro: 'Usuário não autenticado'
        });
    }

    const token = autorizacao.replace('Bearer ', '');
    const usuario = sessoes.get(token);

    if (!usuario) {
        return res.status(401).json({
            erro: 'Sessão expirada'
        });
    }

    req.usuario = usuario;
    req.token = token;

    next();
}

function permitir(...perfis) {
    return (req, res, next) => {
        if (!req.usuario) {
            return res.status(401).json({
                erro: 'Não autenticado'
            });
        }

        if (!perfis.includes(req.usuario.perfil)) {
            return res.status(403).json({
                erro: 'Você não tem permissão para acessar esta função'
            });
        }

        next();
    };
}

function validarCNPJ(cnpj) {
    const numero = String(cnpj || '').replace(/\D/g, '');

    if (numero.length !== 14) {
        return false;
    }

    if (/^(\d)\1{13}$/.test(numero)) {
        return false;
    }

    let soma = 0;
    let peso = 5;

    for (let i = 0; i < 12; i++) {
        soma += Number(numero[i]) * peso;
        peso--;

        if (peso === 1) {
            peso = 9;
        }
    }

    let resto = soma % 11;
    let digito1 = resto < 2 ? 0 : 11 - resto;

    if (Number(numero[12]) !== digito1) {
        return false;
    }

    soma = 0;
    peso = 6;

    for (let i = 0; i < 13; i++) {
        soma += Number(numero[i]) * peso;
        peso--;

        if (peso === 1) {
            peso = 9;
        }
    }

    resto = soma % 11;
    let digito2 = resto < 2 ? 0 : 11 - resto;

    return Number(numero[13]) === digito2;
}

function numeroConta(prefixo) {
    return `${prefixo}-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
}

connection.connect((err) => {
    if (err) {
        console.error(
            'Erro ao conectar ao MySQL:',
            err.message
        );
        return;
    }

    console.log('Conectado ao MySQL com sucesso!');
});

app.get('/', (req, res) => {
    res.sendFile(
        path.join(frontendPath, 'index.html')
    );
});

app.get('/login', (req, res) => {
    res.sendFile(
        path.join(frontendPath, 'login.html')
    );
});


/* =========================
   CADASTRO
========================= */

app.post('/api/cadastro', (req, res) => {

    const {
        nome,
        cpf,
        email,
        telefone,
        login,
        senha
    } = req.body;

    if (!nome || !cpf || !login || !senha) {
        return res.status(400).json({
            erro: 'Preencha os campos obrigatórios'
        });
    }

    if (senha.length < 6) {
        return res.status(400).json({
            erro: 'A senha deve ter no mínimo 6 caracteres'
        });
    }

    connection.beginTransaction((err) => {

        if (err) {
            return res.status(500).json({
                erro: 'Erro ao iniciar cadastro'
            });
        }

        const contaNumero = numeroConta('C');

        connection.query(
            'INSERT INTO conta (numero) VALUES (?)',
            [contaNumero],
            (err, contaResult) => {

                if (err) {
                    return connection.rollback(() => {
                        res.status(500).json({
                            erro: 'Erro ao criar conta'
                        });
                    });
                }

                const idConta = contaResult.insertId;

                connection.query(
                    `INSERT INTO cliente
                    (nome, cpf, email, telefone, id_conta)
                    VALUES (?, ?, ?, ?, ?)`,
                    [
                        nome,
                        cpf,
                        email || null,
                        telefone || null,
                        idConta
                    ],
                    (err, clienteResult) => {

                        if (err) {
                            return connection.rollback(() => {
                                res.status(400).json({
                                    erro:
                                        err.code === 'ER_DUP_ENTRY'
                                            ? 'CPF já cadastrado'
                                            : 'Erro ao criar cliente'
                                });
                            });
                        }

                        const idCliente =
                            clienteResult.insertId;

                        const senhaHash =
                            criarSenha(senha);

                        connection.query(
                            `INSERT INTO usuario
                            (login, senha_hash, perfil, id_cliente)
                            VALUES (?, ?, 'CLIENTE', ?)`,
                            [
                                login,
                                senhaHash,
                                idCliente
                            ],
                            (err) => {

                                if (err) {
                                    return connection.rollback(() => {
                                        res.status(400).json({
                                            erro:
                                                err.code === 'ER_DUP_ENTRY'
                                                    ? 'Usuário já cadastrado'
                                                    : 'Erro ao criar usuário'
                                        });
                                    });
                                }

                                connection.commit((err) => {

                                    if (err) {
                                        return connection.rollback(() => {
                                            res.status(500).json({
                                                erro:
                                                    'Erro ao finalizar cadastro'
                                            });
                                        });
                                    }

                                    const token =
                                        criarToken();

                                    const usuario = {
                                        id: idCliente,
                                        nome,
                                        perfil: 'CLIENTE',
                                        id_cliente: idCliente
                                    };

                                    sessoes.set(
                                        token,
                                        usuario
                                    );

                                    res.status(201).json({
                                        token,
                                        user: usuario
                                    });
                                });
                            }
                        );
                    }
                );
            }
        );
    });
});


/* =========================
   LOGIN
========================= */

app.post('/api/login', (req, res) => {

    const {
        login,
        senha
    } = req.body;

    if (!login || !senha) {
        return res.status(400).json({
            erro: 'Informe o usuário e a senha'
        });
    }

    const sql = `
        SELECT
            u.id_usuario,
            u.login,
            u.senha_hash,
            u.perfil,
            u.id_cliente,
            c.nome
        FROM usuario u
        LEFT JOIN cliente c
            ON c.id_cliente = u.id_cliente
        WHERE u.login = ?
        AND u.ativo = 1
    `;

    connection.query(
        sql,
        [login],
        (err, results) => {

            if (err) {
                return res.status(500).json({
                    erro: 'Erro ao realizar login'
                });
            }

            if (!results.length) {
                return res.status(401).json({
                    erro: 'Usuário ou senha incorretos'
                });
            }

            const usuarioBanco = results[0];

            if (
                !verificarSenha(
                    senha,
                    usuarioBanco.senha_hash
                )
            ) {
                return res.status(401).json({
                    erro: 'Usuário ou senha incorretos'
                });
            }

            const token = criarToken();

            const usuario = {
                id: usuarioBanco.id_usuario,
                nome:
                    usuarioBanco.nome ||
                    usuarioBanco.login,
                perfil: usuarioBanco.perfil,
                id_cliente:
                    usuarioBanco.id_cliente
            };

            sessoes.set(token, usuario);

            res.json({
                token,
                user: usuario
            });
        }
    );
});


/* =========================
   ALTERAR SENHA
========================= */

app.post(
    '/api/senha',
    autenticar,
    (req, res) => {

        const {
            atual,
            nova
        } = req.body;

        if (!atual || !nova) {
            return res.status(400).json({
                erro:
                    'Informe a senha atual e a nova senha'
            });
        }

        if (nova.length < 6) {
            return res.status(400).json({
                erro:
                    'A nova senha deve ter no mínimo 6 caracteres'
            });
        }

        connection.query(
            `SELECT senha_hash
             FROM usuario
             WHERE id_usuario = ?`,
            [req.usuario.id],
            (err, results) => {

                if (err || !results.length) {
                    return res.status(500).json({
                        erro: 'Erro ao buscar usuário'
                    });
                }

                if (
                    !verificarSenha(
                        atual,
                        results[0].senha_hash
                    )
                ) {
                    return res.status(400).json({
                        erro: 'Senha atual incorreta'
                    });
                }

                const novaSenha =
                    criarSenha(nova);

                connection.query(
                    `UPDATE usuario
                     SET senha_hash = ?
                     WHERE id_usuario = ?`,
                    [
                        novaSenha,
                        req.usuario.id
                    ],
                    (err) => {

                        if (err) {
                            return res.status(500).json({
                                erro:
                                    'Erro ao alterar senha'
                            });
                        }

                        res.json({
                            mensagem:
                                'Senha alterada com sucesso'
                        });
                    }
                );
            }
        );
    }
);


/* =========================
   USUÁRIOS
========================= */

app.get(
    '/api/usuarios',
    autenticar,
    permitir('ADMIN'),
    (req, res) => {

        const sql = `
            SELECT
                u.id_usuario AS id,
                u.login,
                u.perfil,
                u.ativo,
                c.nome AS cliente
            FROM usuario u
            LEFT JOIN cliente c
                ON c.id_cliente = u.id_cliente
            ORDER BY u.id_usuario DESC
        `;

        connection.query(
            sql,
            (err, results) => {

                if (err) {
                    return res.status(500).json({
                        erro:
                            'Erro ao buscar usuários'
                    });
                }

                res.json(results);
            }
        );
    }
);

app.post(
    '/api/usuarios',
    autenticar,
    permitir('ADMIN'),
    (req, res) => {

        const {
            login,
            senha,
            perfil,
            id_cliente
        } = req.body;

        const perfisValidos = [
            'ADMIN',
            'OPERADOR',
            'CLIENTE'
        ];

        if (!login || !senha || !perfil) {
            return res.status(400).json({
                erro:
                    'Login, senha e perfil são obrigatórios'
            });
        }

        if (senha.length < 6) {
            return res.status(400).json({
                erro:
                    'A senha deve ter no mínimo 6 caracteres'
            });
        }

        if (!perfisValidos.includes(perfil)) {
            return res.status(400).json({
                erro: 'Perfil inválido'
            });
        }

        if (
            perfil === 'CLIENTE' &&
            !id_cliente
        ) {
            return res.status(400).json({
                erro:
                    'Selecione o cliente'
            });
        }

        const senhaHash =
            criarSenha(senha);

        connection.query(
            `INSERT INTO usuario
            (login, senha_hash, perfil, id_cliente)
            VALUES (?, ?, ?, ?)`,
            [
                login,
                senhaHash,
                perfil,
                perfil === 'CLIENTE'
                    ? id_cliente
                    : null
            ],
            (err, result) => {

                if (err) {
                    return res.status(400).json({
                        erro:
                            err.code === 'ER_DUP_ENTRY'
                                ? 'Login já cadastrado'
                                : 'Erro ao criar usuário'
                    });
                }

                res.status(201).json({
                    id_usuario:
                        result.insertId,
                    mensagem:
                        'Usuário criado com sucesso'
                });
            }
        );
    }
);

app.put(
    '/api/usuarios/:id/ativo',
    autenticar,
    permitir('ADMIN'),
    (req, res) => {

        const id =
            Number(req.params.id);

        const ativo =
            Number(req.body.ativo) ? 1 : 0;

        if (!id) {
            return res.status(400).json({
                erro: 'Usuário inválido'
            });
        }

        if (
            id === Number(req.usuario.id) &&
            ativo === 0
        ) {
            return res.status(400).json({
                erro:
                    'Você não pode desativar seu próprio usuário'
            });
        }

        connection.query(
            `UPDATE usuario
             SET ativo = ?
             WHERE id_usuario = ?`,
            [
                ativo,
                id
            ],
            (err, result) => {

                if (err) {
                    return res.status(500).json({
                        erro:
                            'Erro ao alterar usuário'
                    });
                }

                if (!result.affectedRows) {
                    return res.status(404).json({
                        erro:
                            'Usuário não encontrado'
                    });
                }

                res.json({
                    mensagem:
                        'Usuário atualizado com sucesso'
                });
            }
        );
    }
);


/* =========================
   LOGOUT
========================= */

app.post(
    '/api/logout',
    autenticar,
    (req, res) => {

        sessoes.delete(req.token);

        res.json({
            mensagem:
                'Sessão encerrada'
        });
    }
);


/* =========================
   CLIENTES
========================= */

app.get(
    '/api/clientes',
    autenticar,
    permitir(
        'ADMIN',
        'OPERADOR'
    ),
    (req, res) => {

        const sql = `
            SELECT
                c.id_cliente AS id,
                c.nome,
                c.cpf,
                c.email,
                c.telefone,
                c.id_conta,
                ct.numero AS conta
            FROM cliente c
            LEFT JOIN conta ct
                ON ct.id_conta = c.id_conta
            ORDER BY c.id_cliente DESC
        `;

        connection.query(
            sql,
            (err, results) => {

                if (err) {
                    return res.status(500).json({
                        erro:
                            'Erro ao buscar clientes'
                    });
                }

                res.json(results);
            }
        );
    }
);

app.post(
    '/api/clientes',
    autenticar,
    permitir(
        'ADMIN',
        'OPERADOR'
    ),
    (req, res) => {

        const {
            nome,
            cpf,
            email,
            telefone,
            id_conta
        } = req.body;

        if (!nome || !cpf) {
            return res.status(400).json({
                erro:
                    'Nome e CPF são obrigatórios'
            });
        }

        function inserirCliente(contaId) {

            connection.query(
                `INSERT INTO cliente
                (nome, cpf, email, telefone, id_conta)
                VALUES (?, ?, ?, ?, ?)`,
                [
                    nome,
                    cpf,
                    email || null,
                    telefone || null,
                    contaId
                ],
                (err, result) => {

                    if (err) {
                        return res.status(400).json({
                            erro:
                                err.code === 'ER_DUP_ENTRY'
                                    ? 'CPF já cadastrado'
                                    : 'Erro ao cadastrar cliente'
                        });
                    }

                    res.status(201).json({
                        id_cliente:
                            result.insertId,
                        mensagem:
                            'Cliente cadastrado com sucesso'
                    });
                }
            );
        }

        if (id_conta) {
            return inserirCliente(id_conta);
        }

        connection.query(
            'INSERT INTO conta (numero) VALUES (?)',
            [numeroConta('C')],
            (err, result) => {

                if (err) {
                    return res.status(500).json({
                        erro:
                            'Erro ao criar conta do cliente'
                    });
                }

                inserirCliente(
                    result.insertId
                );
            }
        );
    }
);


/* =========================
   LOJAS
========================= */

app.get(
    '/api/lojas',
    autenticar,
    permitir(
        'ADMIN',
        'OPERADOR'
    ),
    (req, res) => {

        const sql = `
            SELECT
                l.id_loja AS id,
                l.nome,
                l.tipo,
                l.endereco,
                l.id_conta,
                c.numero AS conta
            FROM loja l
            LEFT JOIN conta c
                ON c.id_conta = l.id_conta
            ORDER BY l.id_loja DESC
        `;

        connection.query(
            sql,
            (err, results) => {

                if (err) {
                    return res.status(500).json({
                        erro:
                            'Erro ao buscar lojas'
                    });
                }

                res.json(results);
            }
        );
    }
);

app.post(
    '/api/lojas',
    autenticar,
    permitir('ADMIN'),
    (req, res) => {

        const {
            nome,
            tipo,
            endereco,
            id_conta
        } = req.body;

        if (!nome) {
            return res.status(400).json({
                erro:
                    'Nome da loja é obrigatório'
            });
        }

        const tipoValido = [
            'Física',
            'Online'
        ];

        if (
            tipo &&
            !tipoValido.includes(tipo)
        ) {
            return res.status(400).json({
                erro:
                    'Tipo de loja inválido'
            });
        }

        function inserirLoja(contaId) {

            connection.query(
                `INSERT INTO loja
                (nome, tipo, endereco, id_conta)
                VALUES (?, ?, ?, ?)`,
                [
                    nome,
                    tipo || 'Física',
                    endereco || null,
                    contaId
                ],
                (err, result) => {

                    if (err) {
                        return res.status(400).json({
                            erro:
                                'Erro ao cadastrar loja'
                        });
                    }

                    res.status(201).json({
                        id_loja:
                            result.insertId,
                        mensagem:
                            'Loja cadastrada com sucesso'
                    });
                }
            );
        }

        if (id_conta) {
            return inserirLoja(id_conta);
        }

        connection.query(
            'INSERT INTO conta (numero) VALUES (?)',
            [numeroConta('L')],
            (err, result) => {

                if (err) {
                    return res.status(500).json({
                        erro:
                            'Erro ao criar conta da loja'
                    });
                }

                inserirLoja(
                    result.insertId
                );
            }
        );
    }
);


/* =========================
   CATEGORIAS
========================= */

app.get(
    '/api/categorias',
    autenticar,
    permitir('ADMIN'),
    (req, res) => {

        connection.query(
            `SELECT
                id_categoria AS id,
                nome,
                descricao
             FROM categoria
             ORDER BY id_categoria DESC`,
            (err, results) => {

                if (err) {
                    return res.status(500).json({
                        erro:
                            'Erro ao buscar categorias'
                    });
                }

                res.json(results);
            }
        );
    }
);

app.post(
    '/api/categorias',
    autenticar,
    permitir('ADMIN'),
    (req, res) => {

        const {
            nome,
            descricao
        } = req.body;

        if (!nome) {
            return res.status(400).json({
                erro: 'Nome é obrigatório'
            });
        }

        connection.query(
            `INSERT INTO categoria
            (nome, descricao)
            VALUES (?, ?)`,
            [
                nome,
                descricao || null
            ],
            (err, result) => {

                if (err) {
                    return res.status(500).json({
                        erro:
                            'Erro ao cadastrar categoria'
                    });
                }

                res.status(201).json({
                    id_categoria:
                        result.insertId,
                    mensagem:
                        'Categoria cadastrada com sucesso'
                });
            }
        );
    }
);


/* =========================
   FORNECEDORES
========================= */

app.get(
    '/api/fornecedores',
    autenticar,
    permitir(
        'ADMIN',
        'OPERADOR'
    ),
    (req, res) => {

        connection.query(
            `SELECT
                id_fornecedor AS id,
                razao_social,
                cnpj,
                email,
                telefone
             FROM fornecedor
             ORDER BY id_fornecedor DESC`,
            (err, results) => {

                if (err) {
                    return res.status(500).json({
                        erro:
                            'Erro ao buscar fornecedores'
                    });
                }

                res.json(results);
            }
        );
    }
);

app.post(
    '/api/fornecedores',
    autenticar,
    permitir('ADMIN'),
    (req, res) => {

        const {
            razao_social,
            cnpj,
            email,
            telefone
        } = req.body;

        if (!razao_social || !cnpj) {
            return res.status(400).json({
                erro:
                    'Razão social e CNPJ são obrigatórios'
            });
        }

        if (!validarCNPJ(cnpj)) {
            return res.status(400).json({
                erro:
                    'CNPJ inválido'
            });
        }

        const cnpjLimpo =
            String(cnpj).replace(/\D/g, '');

        connection.query(
            `INSERT INTO fornecedor
            (razao_social, cnpj, email, telefone)
            VALUES (?, ?, ?, ?)`,
            [
                razao_social,
                cnpjLimpo,
                email || null,
                telefone || null
            ],
            (err, result) => {

                if (err) {
                    return res.status(400).json({
                        erro:
                            err.code === 'ER_DUP_ENTRY'
                                ? 'CNPJ já cadastrado'
                                : 'Erro ao cadastrar fornecedor'
                    });
                }

                res.status(201).json({
                    id_fornecedor:
                        result.insertId,
                    mensagem:
                        'Fornecedor cadastrado com sucesso'
                });
            }
        );
    }
);


/* =========================
   PRODUTOS
========================= */

app.get(
    '/api/produtos',
    autenticar,
    (req, res) => {

        const sql = `
            SELECT
                p.id_produto AS id,
                p.nome,
                p.tendencia,
                p.novidade,
                p.preco,
                p.id_categoria AS categoria,
                p.id_loja AS loja,
                c.nome AS categoria_nome,
                l.nome AS loja_nome,
                COALESCE(
                    SUM(e.quantidade),
                    0
                ) AS estoque,
                MAX(e.id_fornecedor) AS fornecedor
            FROM produto p

            LEFT JOIN categoria c
                ON c.id_categoria = p.id_categoria

            LEFT JOIN loja l
                ON l.id_loja = p.id_loja

            LEFT JOIN estoque e
                ON e.id_produto = p.id_produto

            GROUP BY
                p.id_produto,
                p.nome,
                p.tendencia,
                p.novidade,
                p.preco,
                p.id_categoria,
                p.id_loja,
                c.nome,
                l.nome

            ORDER BY p.id_produto DESC
        `;

        connection.query(
            sql,
            (err, results) => {

                if (err) {
                    return res.status(500).json({
                        erro:
                            'Erro ao buscar produtos'
                    });
                }

                res.json(results);
            }
        );
    }
);

app.post(
    '/api/produtos',
    autenticar,
    permitir('ADMIN'),
    (req, res) => {

        const {
            nome,
            tendencia,
            novidade,
            preco,
            categoria,
            loja,
            fornecedor,
            estoque
        } = req.body;

        if (
            !nome ||
            preco === undefined ||
            !categoria ||
            !loja
        ) {
            return res.status(400).json({
                erro:
                    'Preencha os campos obrigatórios'
            });
        }

        const precoNumero =
            Number(preco);

        if (
            Number.isNaN(precoNumero) ||
            precoNumero < 0
        ) {
            return res.status(400).json({
                erro:
                    'Preço inválido'
            });
        }

        if (
            estoque !== undefined &&
            Number(estoque) < 0
        ) {
            return res.status(400).json({
                erro:
                    'Quantidade de estoque inválida'
            });
        }

        connection.beginTransaction((err) => {

            if (err) {
                return res.status(500).json({
                    erro:
                        'Erro ao iniciar cadastro'
                });
            }

            connection.query(
                `SELECT id_categoria
                 FROM categoria
                 WHERE id_categoria = ?`,
                [categoria],
                (err, categorias) => {

                    if (err) {
                        return connection.rollback(() => {
                            res.status(500).json({
                                erro:
                                    'Erro ao validar categoria'
                            });
                        });
                    }

                    if (!categorias.length) {
                        return connection.rollback(() => {
                            res.status(400).json({
                                erro:
                                    'Categoria não encontrada'
                            });
                        });
                    }

                    connection.query(
                        `SELECT id_loja
                         FROM loja
                         WHERE id_loja = ?`,
                        [loja],
                        (err, lojas) => {

                            if (err) {
                                return connection.rollback(() => {
                                    res.status(500).json({
                                        erro:
                                            'Erro ao validar loja'
                                    });
                                });
                            }

                            if (!lojas.length) {
                                return connection.rollback(() => {
                                    res.status(400).json({
                                        erro:
                                            'Loja não encontrada'
                                    });
                                });
                            }

                            connection.query(
                                `INSERT INTO produto
                                (
                                    nome,
                                    tendencia,
                                    novidade,
                                    preco,
                                    id_categoria,
                                    id_loja
                                )
                                VALUES (?, ?, ?, ?, ?, ?)`,
                                [
                                    nome,
                                    tendencia ? 1 : 0,
                                    novidade ? 1 : 0,
                                    precoNumero,
                                    categoria,
                                    loja
                                ],
                                (err, result) => {

                                    if (err) {
                                        return connection.rollback(() => {
                                            res.status(400).json({
                                                erro:
                                                    'Erro ao cadastrar produto'
                                            });
                                        });
                                    }

                                    const idProduto =
                                        result.insertId;

                                    if (
                                        !fornecedor ||
                                        estoque === undefined ||
                                        Number(estoque) === 0
                                    ) {
                                        return connection.commit((err) => {

                                            if (err) {
                                                return connection.rollback(() => {
                                                    res.status(500).json({
                                                        erro:
                                                            'Erro ao finalizar cadastro'
                                                    });
                                                });
                                            }

                                            res.status(201).json({
                                                id_produto:
                                                    idProduto,
                                                mensagem:
                                                    'Produto cadastrado com sucesso'
                                            });
                                        });
                                    }

                                    connection.query(
                                        `SELECT id_fornecedor
                                         FROM fornecedor
                                         WHERE id_fornecedor = ?`,
                                        [fornecedor],
                                        (err, fornecedores) => {

                                            if (err) {
                                                return connection.rollback(() => {
                                                    res.status(500).json({
                                                        erro:
                                                            'Erro ao validar fornecedor'
                                                    });
                                                });
                                            }

                                            if (!fornecedores.length) {
                                                return connection.rollback(() => {
                                                    res.status(400).json({
                                                        erro:
                                                            'Fornecedor não encontrado'
                                                    });
                                                });
                                            }

                                            connection.query(
                                                `INSERT INTO estoque
                                                (
                                                    id_produto,
                                                    id_fornecedor,
                                                    quantidade
                                                )
                                                VALUES (?, ?, ?)`,
                                                [
                                                    idProduto,
                                                    fornecedor,
                                                    Number(estoque)
                                                ],
                                                (err) => {

                                                    if (err) {
                                                        return connection.rollback(() => {
                                                            res.status(400).json({
                                                                erro:
                                                                    'Erro ao cadastrar estoque'
                                                            });
                                                        });
                                                    }

                                                    connection.commit((err) => {

                                                        if (err) {
                                                            return connection.rollback(() => {
                                                                res.status(500).json({
                                                                    erro:
                                                                        'Erro ao finalizar cadastro'
                                                                });
                                                            });
                                                        }

                                                        res.status(201).json({
                                                            id_produto:
                                                                idProduto,
                                                            mensagem:
                                                                'Produto cadastrado com sucesso'
                                                        });
                                                    });
                                                }
                                            );
                                        }
                                    );
                                }
                            );
                        }
                    );
                }
            );
        });
    }
);


/* =========================
   ESTOQUE
========================= */

app.get(
    '/api/estoque',
    autenticar,
    permitir(
        'ADMIN',
        'OPERADOR'
    ),
    (req, res) => {

        const sql = `
            SELECT
                e.id_estoque AS id,
                e.id_produto AS produto,
                e.id_fornecedor AS fornecedor,
                e.quantidade,
                p.nome AS produto_nome,
                f.razao_social AS fornecedor_nome
            FROM estoque e
            INNER JOIN produto p
                ON p.id_produto = e.id_produto
            INNER JOIN fornecedor f
                ON f.id_fornecedor = e.id_fornecedor
            ORDER BY e.id_estoque DESC
        `;

        connection.query(
            sql,
            (err, results) => {

                if (err) {
                    return res.status(500).json({
                        erro:
                            'Erro ao buscar estoque'
                    });
                }

                res.json(results);
            }
        );
    }
);

app.post(
    '/api/estoque',
    autenticar,
    permitir(
        'ADMIN',
        'OPERADOR'
    ),
    (req, res) => {

        const {
            produto,
            fornecedor,
            quantidade
        } = req.body;

        if (
            !produto ||
            !fornecedor ||
            quantidade === undefined
        ) {
            return res.status(400).json({
                erro:
                    'Preencha os campos obrigatórios'
            });
        }

        const qtd =
            Number(quantidade);

        if (
            Number.isNaN(qtd) ||
            qtd <= 0 ||
            !Number.isInteger(qtd)
        ) {
            return res.status(400).json({
                erro:
                    'Quantidade deve ser um número inteiro maior que zero'
            });
        }

        connection.query(
            `SELECT id_produto
             FROM produto
             WHERE id_produto = ?`,
            [produto],
            (err, produtos) => {

                if (err) {
                    return res.status(500).json({
                        erro:
                            'Erro ao validar produto'
                    });
                }

                if (!produtos.length) {
                    return res.status(400).json({
                        erro:
                            'Produto não encontrado'
                    });
                }

                connection.query(
                    `SELECT id_fornecedor
                     FROM fornecedor
                     WHERE id_fornecedor = ?`,
                    [fornecedor],
                    (err, fornecedores) => {

                        if (err) {
                            return res.status(500).json({
                                erro:
                                    'Erro ao validar fornecedor'
                            });
                        }

                        if (!fornecedores.length) {
                            return res.status(400).json({
                                erro:
                                    'Fornecedor não encontrado'
                            });
                        }

                        connection.query(
                            `INSERT INTO estoque
                            (
                                id_produto,
                                id_fornecedor,
                                quantidade
                            )
                            VALUES (?, ?, ?)`,
                            [
                                produto,
                                fornecedor,
                                qtd
                            ],
                            (err, result) => {

                                if (err) {
                                    return res.status(400).json({
                                        erro:
                                            'Erro ao cadastrar estoque'
                                    });
                                }

                                res.status(201).json({
                                    id_estoque:
                                        result.insertId,
                                    mensagem:
                                        'Estoque cadastrado com sucesso'
                                });
                            }
                        );
                    }
                );
            }
        );
    }
);


/* =========================
   VENDAS
========================= */

app.get(
    '/api/vendas',
    autenticar,
    permitir(
        'ADMIN',
        'OPERADOR'
    ),
    (req, res) => {

        const sql = `
            SELECT
                v.id_venda AS id,
                v.data,
                v.valor_total AS total,
                v.canal,
                v.status,
                v.id_cliente AS cliente,
                v.id_loja AS loja,
                c.nome AS cliente_nome,
                l.nome AS loja_nome
            FROM venda v
            INNER JOIN cliente c
                ON c.id_cliente = v.id_cliente
            INNER JOIN loja l
                ON l.id_loja = v.id_loja
            ORDER BY v.id_venda DESC
        `;

        connection.query(
            sql,
            (err, results) => {

                if (err) {
                    return res.status(500).json({
                        erro:
                            'Erro ao buscar vendas'
                    });
                }

                res.json(results);
            }
        );
    }
);


/* =========================
   CRIAR VENDA
========================= */

app.post(
    '/api/vendas',
    autenticar,
    permitir(
        'ADMIN',
        'OPERADOR'
    ),
    (req, res) => {

        const {
            cliente,
            loja,
            canal,
            forma,
            valorPago,
            itens
        } = req.body;

        const idCliente =
            Number(cliente);

        const idLoja =
            Number(loja);

        if (
            !idCliente ||
            !idLoja ||
            !canal
        ) {
            return res.status(400).json({
                erro:
                    'Cliente, loja e canal são obrigatórios'
            });
        }

        if (
            !Array.isArray(itens) ||
            !itens.length
        ) {
            return res.status(400).json({
                erro:
                    'Adicione pelo menos um produto'
            });
        }

        const itensAgrupados = new Map();

        for (const item of itens) {

            const idProduto =
                Number(item.produto);

            const quantidade =
                Number(item.quantidade);

            if (
                !idProduto ||
                !Number.isInteger(quantidade) ||
                quantidade <= 0
            ) {
                return res.status(400).json({
                    erro:
                        'Produto ou quantidade inválida'
                });
            }

            const atual =
                itensAgrupados.get(idProduto) || 0;

            itensAgrupados.set(
                idProduto,
                atual + quantidade
            );
        }

        let pagamentoInicial =
            valorPago === undefined ||
            valorPago === null ||
            valorPago === ''
                ? 0
                : Number(valorPago);

        if (
            Number.isNaN(pagamentoInicial) ||
            pagamentoInicial < 0
        ) {
            return res.status(400).json({
                erro:
                    'Valor de pagamento inválido'
            });
        }

        if (
            pagamentoInicial > 0 &&
            !forma
        ) {
            return res.status(400).json({
                erro:
                    'Informe a forma de pagamento'
            });
        }

        const formasValidas = [
            'PIX',
            'Cartão',
            'Boleto'
        ];

        if (
            pagamentoInicial > 0 &&
            !formasValidas.includes(forma)
        ) {
            return res.status(400).json({
                erro:
                    'Forma de pagamento inválida'
            });
        }

        connection.beginTransaction((err) => {

            if (err) {
                return res.status(500).json({
                    erro:
                        'Erro ao iniciar venda'
                });
            }

            connection.query(
                `SELECT id_cliente
                 FROM cliente
                 WHERE id_cliente = ?`,
                [idCliente],
                (err, clientes) => {

                    if (err) {
                        return connection.rollback(() => {
                            res.status(500).json({
                                erro:
                                    'Erro ao validar cliente'
                            });
                        });
                    }

                    if (!clientes.length) {
                        return connection.rollback(() => {
                            res.status(400).json({
                                erro:
                                    'Cliente não encontrado'
                            });
                        });
                    }

                    connection.query(
                        `SELECT id_loja
                         FROM loja
                         WHERE id_loja = ?`,
                        [idLoja],
                        (err, lojas) => {

                            if (err) {
                                return connection.rollback(() => {
                                    res.status(500).json({
                                        erro:
                                            'Erro ao validar loja'
                                    });
                                });
                            }

                            if (!lojas.length) {
                                return connection.rollback(() => {
                                    res.status(400).json({
                                        erro:
                                            'Loja não encontrada'
                                    });
                                });
                            }

                            const idsProdutos =
                                [...itensAgrupados.keys()];

                            connection.query(
                                `SELECT
                                    id_produto,
                                    preco
                                 FROM produto
                                 WHERE id_produto IN (?)`,
                                [idsProdutos],
                                (err, produtos) => {

                                    if (err) {
                                        return connection.rollback(() => {
                                            res.status(500).json({
                                                erro:
                                                    'Erro ao consultar produtos'
                                            });
                                        });
                                    }

                                    if (
                                        produtos.length !==
                                        idsProdutos.length
                                    ) {
                                        return connection.rollback(() => {
                                            res.status(400).json({
                                                erro:
                                                    'Um ou mais produtos não foram encontrados'
                                            });
                                        });
                                    }

                                    const mapaProdutos =
                                        new Map();

                                    produtos.forEach(produto => {
                                        mapaProdutos.set(
                                            Number(produto.id_produto),
                                            produto
                                        );
                                    });

                                    connection.query(
                                        `SELECT
                                            id_estoque,
                                            id_produto,
                                            quantidade
                                         FROM estoque
                                         WHERE id_produto IN (?)
                                         AND quantidade > 0
                                         ORDER BY id_estoque
                                         FOR UPDATE`,
                                        [idsProdutos],
                                        (err, estoques) => {

                                            if (err) {
                                                return connection.rollback(() => {
                                                    res.status(500).json({
                                                        erro:
                                                            'Erro ao consultar estoque'
                                                    });
                                                });
                                            }

                                            const estoquePorProduto =
                                                new Map();

                                            estoques.forEach(estoque => {

                                                const id =
                                                    Number(
                                                        estoque.id_produto
                                                    );

                                                if (
                                                    !estoquePorProduto.has(id)
                                                ) {
                                                    estoquePorProduto.set(
                                                        id,
                                                        []
                                                    );
                                                }

                                                estoquePorProduto
                                                    .get(id)
                                                    .push(estoque);
                                            });

                                            const itensVenda = [];
                                            let total = 0;

                                            for (
                                                const [
                                                    idProduto,
                                                    quantidadeSolicitada
                                                ]
                                                of itensAgrupados
                                            ) {

                                                const produto =
                                                    mapaProdutos.get(
                                                        idProduto
                                                    );

                                                const lotes =
                                                    estoquePorProduto.get(
                                                        idProduto
                                                    ) || [];

                                                let restante =
                                                    quantidadeSolicitada;

                                                const estoqueTotal =
                                                    lotes.reduce(
                                                        (
                                                            soma,
                                                            lote
                                                        ) =>
                                                            soma +
                                                            Number(
                                                                lote.quantidade
                                                            ),
                                                        0
                                                    );

                                                if (
                                                    estoqueTotal <
                                                    quantidadeSolicitada
                                                ) {
                                                    return connection.rollback(() => {
                                                        res.status(400).json({
                                                            erro:
                                                                `Estoque insuficiente para o produto ${idProduto}`
                                                        });
                                                    });
                                                }

                                                for (
                                                    const lote
                                                    of lotes
                                                ) {

                                                    if (
                                                        restante <= 0
                                                    ) {
                                                        break;
                                                    }

                                                    const disponivel =
                                                        Number(
                                                            lote.quantidade
                                                        );

                                                    const usado =
                                                        Math.min(
                                                            restante,
                                                            disponivel
                                                        );

                                                    itensVenda.push({
                                                        produto:
                                                            idProduto,
                                                        estoque:
                                                            lote.id_estoque,
                                                        quantidade:
                                                            usado,
                                                        preco:
                                                            Number(
                                                                produto.preco
                                                            )
                                                    });

                                                    restante -= usado;

                                                    total +=
                                                        Number(
                                                            produto.preco
                                                        ) * usado;
                                                }
                                            }

                                            if (
                                                pagamentoInicial >
                                                total
                                            ) {
                                                return connection.rollback(() => {
                                                    res.status(400).json({
                                                        erro:
                                                            'O pagamento não pode ser maior que o total da venda'
                                                    });
                                                });
                                            }

                                            connection.query(
                                                `INSERT INTO venda
                                                (
                                                    valor_total,
                                                    canal,
                                                    status,
                                                    id_cliente,
                                                    id_loja
                                                )
                                                VALUES (?, ?, 'ABERTA', ?, ?)`,
                                                [
                                                    total,
                                                    canal,
                                                    idCliente,
                                                    idLoja
                                                ],
                                                (err, vendaResult) => {

                                                    if (err) {
                                                        return connection.rollback(() => {
                                                            res.status(400).json({
                                                                erro:
                                                                    'Erro ao cadastrar venda'
                                                            });
                                                        });
                                                    }

                                                    const idVenda =
                                                        vendaResult.insertId;

                                                    let concluidos = 0;

                                                    function erroItem(mensagem) {
                                                        connection.rollback(() => {
                                                            res.status(500).json({
                                                                erro:
                                                                    mensagem
                                                            });
                                                        });
                                                    }

                                                    for (
                                                        const item
                                                        of itensVenda
                                                    ) {

                                                        connection.query(
                                                            `INSERT INTO item_venda
                                                            (
                                                                id_venda,
                                                                id_produto,
                                                                id_estoque,
                                                                quantidade,
                                                                preco_unitario
                                                            )
                                                            VALUES (?, ?, ?, ?, ?)`,
                                                            [
                                                                idVenda,
                                                                item.produto,
                                                                item.estoque,
                                                                item.quantidade,
                                                                item.preco
                                                            ],
                                                            (err) => {

                                                                if (err) {
                                                                    return erroItem(
                                                                        'Erro ao registrar item da venda'
                                                                    );
                                                                }

                                                                connection.query(
                                                                    `UPDATE estoque
                                                                     SET quantidade =
                                                                         quantidade - ?
                                                                     WHERE id_estoque = ?
                                                                     AND quantidade >= ?`,
                                                                    [
                                                                        item.quantidade,
                                                                        item.estoque,
                                                                        item.quantidade
                                                                    ],
                                                                    (err, updateResult) => {

                                                                        if (err) {
                                                                            return erroItem(
                                                                                'Erro ao atualizar estoque'
                                                                            );
                                                                        }

                                                                        if (
                                                                            !updateResult.affectedRows
                                                                        ) {
                                                                            return erroItem(
                                                                                'Estoque insuficiente'
                                                                            );
                                                                        }

                                                                        concluidos++;

                                                                        if (
                                                                            concluidos ===
                                                                            itensVenda.length
                                                                        ) {
                                                                            finalizarVenda();
                                                                        }
                                                                    }
                                                                );
                                                            }
                                                        );
                                                    }

                                                    function finalizarVenda() {

                                                        const status =
                                                            pagamentoInicial >= total
                                                                ? 'CONCLUIDO'
                                                                : 'ABERTA';

                                                        connection.query(
                                                            `UPDATE venda
                                                             SET status = ?
                                                             WHERE id_venda = ?`,
                                                            [
                                                                status,
                                                                idVenda
                                                            ],
                                                            (err) => {

                                                                if (err) {
                                                                    return erroItem(
                                                                        'Erro ao atualizar status da venda'
                                                                    );
                                                                }

                                                                if (
                                                                    pagamentoInicial <= 0
                                                                ) {
                                                                    return finalizar();
                                                                }

                                                                connection.query(
                                                                    `INSERT INTO pagamento
                                                                    (
                                                                        id_venda,
                                                                        forma,
                                                                        valor,
                                                                        status
                                                                    )
                                                                    VALUES (?, ?, ?, 'CONCLUIDO')`,
                                                                    [
                                                                        idVenda,
                                                                        forma,
                                                                        pagamentoInicial
                                                                    ],
                                                                    (err) => {

                                                                        if (err) {
                                                                            return erroItem(
                                                                                'Erro ao registrar pagamento'
                                                                            );
                                                                        }

                                                                        connection.query(
                                                                            `UPDATE conta ct
                                                                             INNER JOIN loja l
                                                                                 ON l.id_conta = ct.id_conta
                                                                             SET ct.saldo =
                                                                                 ct.saldo + ?
                                                                             WHERE l.id_loja = ?`,
                                                                            [
                                                                                pagamentoInicial,
                                                                                idLoja
                                                                            ],
                                                                            (err) => {

                                                                                if (err) {
                                                                                    return erroItem(
                                                                                        'Erro ao atualizar saldo da loja'
                                                                                    );
                                                                                }

                                                                                finalizar();
                                                                            }
                                                                        );
                                                                    }
                                                                );
                                                            }
                                                        );
                                                    }

                                                    function finalizar() {

                                                        connection.commit(
                                                            (err) => {

                                                                if (err) {
                                                                    return connection.rollback(() => {
                                                                        res.status(500).json({
                                                                            erro:
                                                                                'Erro ao finalizar venda'
                                                                        });
                                                                    });
                                                                }

                                                                res.status(201).json({
                                                                    id:
                                                                        idVenda,
                                                                    id_venda:
                                                                        idVenda,
                                                                    total,
                                                                    status:
                                                                        pagamentoInicial >= total
                                                                            ? 'CONCLUIDO'
                                                                            : 'ABERTA',
                                                                    mensagem:
                                                                        'Venda realizada com sucesso'
                                                                });
                                                            }
                                                        );
                                                    }
                                                }
                                            );
                                        }
                                    );
                                }
                            );
                        }
                    );
                }
            );
        });
    }
);


/* =========================
   VENDAS ABERTAS
========================= */

app.get(
    '/api/vendas/abertas',
    autenticar,
    permitir(
        'ADMIN',
        'OPERADOR'
    ),
    (req, res) => {

        const sql = `
            SELECT
                v.id_venda AS id,
                c.nome AS cliente,
                v.valor_total AS total,
                COALESCE(
                    SUM(p.valor),
                    0
                ) AS pago,
                GREATEST(
                    v.valor_total -
                    COALESCE(
                        SUM(p.valor),
                        0
                    ),
                    0
                ) AS restante
            FROM venda v

            INNER JOIN cliente c
                ON c.id_cliente = v.id_cliente

            LEFT JOIN pagamento p
                ON p.id_venda = v.id_venda

            WHERE v.status = 'ABERTA'

            GROUP BY
                v.id_venda,
                c.nome,
                v.valor_total

            ORDER BY v.id_venda DESC
        `;

        connection.query(
            sql,
            (err, results) => {

                if (err) {
                    return res.status(500).json({
                        erro:
                            'Erro ao buscar pendências'
                    });
                }

                res.json(results);
            }
        );
    }
);


/* =========================
   PAGAMENTOS
========================= */

app.get(
    '/api/pagamentos',
    autenticar,
    permitir(
        'ADMIN',
        'OPERADOR'
    ),
    (req, res) => {

        const sql = `
            SELECT
                p.id_pagamento AS id,
                p.id_venda AS venda,
                p.forma,
                p.valor,
                p.status,
                p.data
            FROM pagamento p
            ORDER BY p.id_pagamento DESC
        `;

        connection.query(
            sql,
            (err, results) => {

                if (err) {
                    return res.status(500).json({
                        erro:
                            'Erro ao buscar pagamentos'
                    });
                }

                res.json(results);
            }
        );
    }
);

app.post(
    '/api/pagamentos',
    autenticar,
    permitir(
        'ADMIN',
        'OPERADOR'
    ),
    (req, res) => {

        const {
            venda,
            forma,
            valor
        } = req.body;

        const formasValidas = [
            'PIX',
            'Cartão',
            'Boleto'
        ];

        const idVenda =
            Number(venda);

        const valorPagamento =
            Number(valor);

        if (
            !idVenda ||
            !forma ||
            valor === undefined
        ) {
            return res.status(400).json({
                erro:
                    'Preencha os campos obrigatórios'
            });
        }

        if (
            !formasValidas.includes(forma)
        ) {
            return res.status(400).json({
                erro:
                    'Forma de pagamento inválida'
            });
        }

        if (
            Number.isNaN(valorPagamento) ||
            valorPagamento <= 0
        ) {
            return res.status(400).json({
                erro:
                    'Valor do pagamento inválido'
            });
        }

        connection.beginTransaction((err) => {

            if (err) {
                return res.status(500).json({
                    erro:
                        'Erro ao iniciar pagamento'
                });
            }

            connection.query(
                `SELECT
                    v.id_venda,
                    v.valor_total,
                    v.status,
                    v.id_loja,
                    COALESCE(
                        SUM(p.valor),
                        0
                    ) AS pago
                 FROM venda v
                 LEFT JOIN pagamento p
                    ON p.id_venda = v.id_venda
                 WHERE v.id_venda = ?
                 GROUP BY
                    v.id_venda,
                    v.valor_total,
                    v.status,
                    v.id_loja
                 FOR UPDATE`,
                [idVenda],
                (err, results) => {

                    if (err) {
                        return connection.rollback(() => {
                            res.status(500).json({
                                erro:
                                    'Erro ao consultar venda'
                            });
                        });
                    }

                    if (!results.length) {
                        return connection.rollback(() => {
                            res.status(404).json({
                                erro:
                                    'Venda não encontrada'
                            });
                        });
                    }

                    const dados = results[0];

                    const total =
                        Number(
                            dados.valor_total
                        );

                    const pagoAtual =
                        Number(
                            dados.pago
                        );

                    const restante =
                        total - pagoAtual;

                    if (
                        dados.status ===
                        'CONCLUIDO'
                    ) {
                        return connection.rollback(() => {
                            res.status(400).json({
                                erro:
                                    'Esta venda já está quitada'
                            });
                        });
                    }

                    if (
                        valorPagamento >
                        restante
                    ) {
                        return connection.rollback(() => {
                            res.status(400).json({
                                erro:
                                    'O pagamento não pode ser maior que o valor restante'
                            });
                        });
                    }

                    connection.query(
                        `INSERT INTO pagamento
                        (
                            id_venda,
                            forma,
                            valor,
                            status
                        )
                        VALUES (?, ?, ?, 'CONCLUIDO')`,
                        [
                            idVenda,
                            forma,
                            valorPagamento
                        ],
                        (err, result) => {

                            if (err) {
                                return connection.rollback(() => {
                                    res.status(500).json({
                                        erro:
                                            'Erro ao cadastrar pagamento'
                                    });
                                });
                            }

                            const novoPago =
                                pagoAtual +
                                valorPagamento;

                            const novoStatus =
                                novoPago >= total
                                    ? 'CONCLUIDO'
                                    : 'ABERTA';

                            connection.query(
                                `UPDATE venda
                                 SET status = ?
                                 WHERE id_venda = ?`,
                                [
                                    novoStatus,
                                    idVenda
                                ],
                                (err) => {

                                    if (err) {
                                        return connection.rollback(() => {
                                            res.status(500).json({
                                                erro:
                                                    'Erro ao atualizar venda'
                                            });
                                        });
                                    }

                                    connection.query(
                                        `UPDATE conta ct
                                         INNER JOIN loja l
                                             ON l.id_conta = ct.id_conta
                                         SET ct.saldo =
                                             ct.saldo + ?
                                         WHERE l.id_loja = ?`,
                                        [
                                            valorPagamento,
                                            dados.id_loja
                                        ],
                                        (err) => {

                                            if (err) {
                                                return connection.rollback(() => {
                                                    res.status(500).json({
                                                        erro:
                                                            'Erro ao atualizar saldo da loja'
                                                    });
                                                });
                                            }

                                            connection.commit(
                                                (err) => {

                                                    if (err) {
                                                        return connection.rollback(() => {
                                                            res.status(500).json({
                                                                erro:
                                                                    'Erro ao finalizar pagamento'
                                                            });
                                                        });
                                                    }

                                                    res.status(201).json({
                                                        id_pagamento:
                                                            result.insertId,
                                                        status:
                                                            novoStatus,
                                                        restante:
                                                            Math.max(
                                                                total - novoPago,
                                                                0
                                                            ),
                                                        mensagem:
                                                            'Pagamento registrado com sucesso'
                                                    });
                                                }
                                            );
                                        }
                                    );
                                }
                            );
                        }
                    );
                }
            );
        });
    }
);


/* =========================
   EXTRATO
========================= */

app.get(
    '/api/clientes/:id/extrato',
    autenticar,
    (req, res) => {

        let idCliente;

        if (req.params.id === 'me') {
            idCliente = Number(
                req.usuario.id_cliente
            );
        } else {
            idCliente =
                Number(req.params.id);
        }

        if (!idCliente) {
            return res.status(400).json({
                erro:
                    'Cliente inválido'
            });
        }

        if (
            req.usuario.perfil === 'CLIENTE' &&
            Number(req.usuario.id_cliente) !==
            idCliente
        ) {
            return res.status(403).json({
                erro:
                    'Você só pode consultar seu próprio extrato'
            });
        }

        if (
            req.usuario.perfil !== 'CLIENTE' &&
            req.usuario.perfil !== 'ADMIN' &&
            req.usuario.perfil !== 'OPERADOR'
        ) {
            return res.status(403).json({
                erro:
                    'Você não tem permissão para consultar este extrato'
            });
        }

        const sqlConta = `
            SELECT
                c.id_cliente,
                c.nome,
                ct.numero,
                ct.saldo
            FROM cliente c
            LEFT JOIN conta ct
                ON ct.id_conta = c.id_conta
            WHERE c.id_cliente = ?
        `;

        connection.query(
            sqlConta,
            [idCliente],
            (err, conta) => {

                if (err) {
                    return res.status(500).json({
                        erro:
                            'Erro ao buscar conta'
                    });
                }

                if (!conta.length) {
                    return res.status(404).json({
                        erro:
                            'Cliente não encontrado'
                    });
                }

                const sqlVendas = `
                    SELECT
                        v.id_venda AS id,
                        v.data,
                        l.nome AS loja,
                        v.valor_total AS total,
                        COALESCE(
                            SUM(p.valor),
                            0
                        ) AS pago,
                        v.status
                    FROM venda v

                    LEFT JOIN loja l
                        ON l.id_loja = v.id_loja

                    LEFT JOIN pagamento p
                        ON p.id_venda = v.id_venda

                    WHERE v.id_cliente = ?

                    GROUP BY
                        v.id_venda,
                        v.data,
                        l.nome,
                        v.valor_total,
                        v.status

                    ORDER BY v.data DESC
                `;

                connection.query(
                    sqlVendas,
                    [idCliente],
                    (err, vendas) => {

                        if (err) {
                            return res.status(500).json({
                                erro:
                                    'Erro ao buscar extrato'
                            });
                        }

                        res.json({
                            conta: {
                                numero:
                                    conta[0].numero,
                                saldo:
                                    conta[0].saldo
                            },
                            vendas
                        });
                    }
                );
            }
        );
    }
);


/* =========================
   MINHAS COMPRAS
========================= */

app.get(
    '/api/minhas-compras',
    autenticar,
    permitir('CLIENTE'),
    (req, res) => {

        const sql = `
            SELECT
                v.id_venda,
                v.data,
                v.valor_total,
                v.canal,
                v.status,
                l.nome AS loja
            FROM venda v

            LEFT JOIN loja l
                ON l.id_loja = v.id_loja

            WHERE v.id_cliente = ?

            ORDER BY v.data DESC
        `;

        connection.query(
            sql,
            [req.usuario.id_cliente],
            (err, results) => {

                if (err) {
                    return res.status(500).json({
                        erro:
                            'Erro ao buscar suas compras'
                    });
                }

                res.json(results);
            }
        );
    }
);


/* =========================
   CONTAS
========================= */

app.get(
    '/api/contas',
    autenticar,
    permitir('ADMIN'),
    (req, res) => {

        const sql = `
            SELECT
                c.id_conta AS id,

                CASE
                    WHEN cl.id_cliente IS NOT NULL
                        THEN 'Cliente'

                    WHEN l.id_loja IS NOT NULL
                        THEN 'Loja'

                    ELSE 'Conta'
                END AS tipo,

                COALESCE(
                    cl.nome,
                    l.nome,
                    '-'
                ) AS nome,

                c.numero,
                c.saldo

            FROM conta c

            LEFT JOIN cliente cl
                ON cl.id_conta = c.id_conta

            LEFT JOIN loja l
                ON l.id_conta = c.id_conta

            ORDER BY c.id_conta DESC
        `;

        connection.query(
            sql,
            (err, results) => {

                if (err) {
                    return res.status(500).json({
                        erro:
                            'Erro ao buscar contas'
                    });
                }

                res.json(results);
            }
        );
    }
);


/* =========================
   RELATÓRIOS
========================= */

app.get(
    '/api/relatorios',
    autenticar,
    permitir('ADMIN'),
    (req, res) => {

        const dados = {};

        connection.query(
            `SELECT
                COUNT(*) AS vendas,
                COALESCE(
                    SUM(valor_total),
                    0
                ) AS faturamento
             FROM venda`,
            (err, vendaResult) => {

                if (err) {
                    return res.status(500).json({
                        erro:
                            'Erro ao gerar relatório'
                    });
                }

                dados.vendas =
                    Number(
                        vendaResult[0].vendas
                    );

                dados.faturamento =
                    Number(
                        vendaResult[0].faturamento
                    );

                dados.ticket =
                    dados.vendas > 0
                        ? dados.faturamento /
                          dados.vendas
                        : 0;

                connection.query(
                    `SELECT
                        COALESCE(
                            SUM(valor),
                            0
                        ) AS recebido
                     FROM pagamento`,
                    (err, recebidoResult) => {

                        if (err) {
                            return res.status(500).json({
                                erro:
                                    'Erro ao gerar relatório'
                            });
                        }

                        dados.recebido =
                            Number(
                                recebidoResult[0].recebido
                            );

                        connection.query(
                            `SELECT
                                p.nome,
                                SUM(
                                    iv.quantidade
                                ) AS qtd,
                                SUM(
                                    iv.quantidade *
                                    iv.preco_unitario
                                ) AS total
                             FROM item_venda iv

                             INNER JOIN produto p
                                ON p.id_produto =
                                   iv.id_produto

                             INNER JOIN venda v
                                ON v.id_venda =
                                   iv.id_venda

                             GROUP BY
                                p.id_produto,
                                p.nome

                             ORDER BY qtd DESC

                             LIMIT 10`,
                            (err, topProdutos) => {

                                if (err) {
                                    return res.status(500).json({
                                        erro:
                                            'Erro ao gerar relatório'
                                    });
                                }

                                dados.topProdutos =
                                    topProdutos;

                                connection.query(
                                    `SELECT
                                        l.nome,
                                        COUNT(
                                            v.id_venda
                                        ) AS vendas,
                                        COALESCE(
                                            SUM(
                                                v.valor_total
                                            ),
                                            0
                                        ) AS total
                                     FROM venda v

                                     INNER JOIN loja l
                                        ON l.id_loja =
                                           v.id_loja

                                     GROUP BY
                                        l.id_loja,
                                        l.nome

                                     ORDER BY total DESC`,
                                    (err, porLoja) => {

                                        if (err) {
                                            return res.status(500).json({
                                                erro:
                                                    'Erro ao gerar relatório'
                                            });
                                        }

                                        dados.porLoja =
                                            porLoja;

                                        connection.query(
                                            `SELECT
                                                forma,
                                                COALESCE(
                                                    SUM(valor),
                                                    0
                                                ) AS total
                                             FROM pagamento

                                             GROUP BY forma

                                             ORDER BY total DESC`,
                                            (err, porForma) => {

                                                if (err) {
                                                    return res.status(500).json({
                                                        erro:
                                                            'Erro ao gerar relatório'
                                                    });
                                                }

                                                dados.porForma =
                                                    porForma;

                                                res.json(
                                                    dados
                                                );
                                            }
                                        );
                                    }
                                );
                            }
                        );
                    }
                );
            }
        );
    }
);


/* =========================
   ERRO DE ROTA
========================= */

app.use('/api', (req, res) => {
    res.status(404).json({
        erro: 'Rota da API não encontrada'
    });
});


/* =========================
   INICIAR SERVIDOR
========================= */

app.listen(
    port,
    () => {
        console.log(
            `Servidor rodando em http://localhost:${port}`
        );
    }
);