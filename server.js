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

        const novoHash = crypto.scryptSync(senha, salt, 64).toString('hex');

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

connection.connect((err) => {
    if (err) {
        console.error('Erro ao conectar ao MySQL:', err.message);
        return;
    }

    console.log('Conectado ao MySQL com sucesso!');
});

app.get('/', (req, res) => {
    res.sendFile(path.join(frontendPath, 'index.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(frontendPath, 'login.html'));
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

        const numeroConta = `C-${Date.now()}`;

        connection.query(
            'INSERT INTO conta (numero) VALUES (?)',
            [numeroConta],
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
                                    erro: err.code === 'ER_DUP_ENTRY'
                                        ? 'CPF já cadastrado'
                                        : 'Erro ao criar cliente'
                                });
                            });
                        }

                        const idCliente = clienteResult.insertId;
                        const senhaHash = criarSenha(senha);

                        connection.query(
                            `INSERT INTO usuario
                            (login, senha_hash, perfil, id_cliente)
                            VALUES (?, ?, 'CLIENTE', ?)`,
                            [login, senhaHash, idCliente],
                            (err) => {
                                if (err) {
                                    return connection.rollback(() => {
                                        res.status(400).json({
                                            erro: err.code === 'ER_DUP_ENTRY'
                                                ? 'Usuário já cadastrado'
                                                : 'Erro ao criar usuário'
                                        });
                                    });
                                }

                                connection.commit((err) => {
                                    if (err) {
                                        return connection.rollback(() => {
                                            res.status(500).json({
                                                erro: 'Erro ao finalizar cadastro'
                                            });
                                        });
                                    }

                                    const token = criarToken();

                                    const usuario = {
                                        id: idCliente,
                                        nome,
                                        perfil: 'CLIENTE',
                                        id_cliente: idCliente
                                    };

                                    sessoes.set(token, usuario);

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
    const { login, senha } = req.body;

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
        LEFT JOIN cliente c ON c.id_cliente = u.id_cliente
        WHERE u.login = ? AND u.ativo = 1
    `;

    connection.query(sql, [login], (err, results) => {
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

        if (!verificarSenha(senha, usuarioBanco.senha_hash)) {
            return res.status(401).json({
                erro: 'Usuário ou senha incorretos'
            });
        }

        const token = criarToken();

        const usuario = {
            id: usuarioBanco.id_usuario,
            nome: usuarioBanco.nome || usuarioBanco.login,
            perfil: usuarioBanco.perfil,
            id_cliente: usuarioBanco.id_cliente
        };

        sessoes.set(token, usuario);

        res.json({
            token,
            user: usuario
        });
    });
});


/* =========================
   ALTERAR SENHA
========================= */

app.post(
    '/api/senha',
    autenticar,
    (req, res) => {
        const { atual, nova } = req.body;

        if (!atual || !nova) {
            return res.status(400).json({
                erro: 'Informe a senha atual e a nova senha'
            });
        }

        if (nova.length < 6) {
            return res.status(400).json({
                erro: 'A nova senha deve ter no mínimo 6 caracteres'
            });
        }

        connection.query(
            'SELECT senha_hash FROM usuario WHERE id_usuario = ?',
            [req.usuario.id],
            (err, results) => {
                if (err || !results.length) {
                    return res.status(500).json({
                        erro: 'Erro ao buscar usuário'
                    });
                }

                if (!verificarSenha(atual, results[0].senha_hash)) {
                    return res.status(400).json({
                        erro: 'Senha atual incorreta'
                    });
                }

                const novaSenha = criarSenha(nova);

                connection.query(
                    'UPDATE usuario SET senha_hash = ? WHERE id_usuario = ?',
                    [novaSenha, req.usuario.id],
                    (err) => {
                        if (err) {
                            return res.status(500).json({
                                erro: 'Erro ao alterar senha'
                            });
                        }

                        res.json({
                            mensagem: 'Senha alterada com sucesso'
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

        connection.query(sql, (err, results) => {
            if (err) {
                return res.status(500).json({
                    erro: 'Erro ao buscar usuários'
                });
            }

            res.json(results);
        });
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
            'VENDEDOR',
            'LOJISTA',
            'CLIENTE'
        ];

        if (!login || !senha || !perfil) {
            return res.status(400).json({
                erro: 'Login, senha e perfil são obrigatórios'
            });
        }

        if (senha.length < 6) {
            return res.status(400).json({
                erro: 'A senha deve ter no mínimo 6 caracteres'
            });
        }

        if (!perfisValidos.includes(perfil)) {
            return res.status(400).json({
                erro: 'Perfil inválido'
            });
        }

        if (perfil === 'CLIENTE' && !id_cliente) {
            return res.status(400).json({
                erro: 'Selecione o cliente'
            });
        }

        const senhaHash = criarSenha(senha);

        connection.query(
            `INSERT INTO usuario
            (login, senha_hash, perfil, id_cliente)
            VALUES (?, ?, ?, ?)`,
            [
                login,
                senhaHash,
                perfil,
                id_cliente || null
            ],
            (err, result) => {
                if (err) {
                    return res.status(400).json({
                        erro: err.code === 'ER_DUP_ENTRY'
                            ? 'Login já cadastrado'
                            : 'Erro ao criar usuário'
                    });
                }

                res.status(201).json({
                    id_usuario: result.insertId,
                    mensagem: 'Usuário criado com sucesso'
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
        const id = Number(req.params.id);
        const ativo = Number(req.body.ativo);

        connection.query(
            'UPDATE usuario SET ativo = ? WHERE id_usuario = ?',
            [ativo ? 1 : 0, id],
            (err) => {
                if (err) {
                    return res.status(500).json({
                        erro: 'Erro ao alterar usuário'
                    });
                }

                res.json({
                    mensagem: 'Usuário atualizado com sucesso'
                });
            }
        );
    }
);


/* =========================
   LOGOUT
========================= */

app.post('/api/logout', autenticar, (req, res) => {
    const token = req.headers.authorization.replace('Bearer ', '');

    sessoes.delete(token);

    res.json({
        mensagem: 'Sessão encerrada'
    });
});


/* =========================
   CLIENTES
========================= */

app.get(
    '/api/clientes',
    autenticar,
    permitir('ADMIN', 'OPERADOR', 'VENDEDOR'),
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
            LEFT JOIN conta ct ON ct.id_conta = c.id_conta
            ORDER BY c.id_cliente DESC
        `;

        connection.query(sql, (err, results) => {
            if (err) {
                return res.status(500).json({
                    erro: 'Erro ao buscar clientes'
                });
            }

            res.json(results);
        });
    }
);

app.post(
    '/api/clientes',
    autenticar,
    permitir('ADMIN', 'OPERADOR', 'VENDEDOR'),
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
                erro: 'Nome e CPF são obrigatórios'
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
                            erro: err.code === 'ER_DUP_ENTRY'
                                ? 'CPF já cadastrado'
                                : 'Erro ao cadastrar cliente'
                        });
                    }

                    res.status(201).json({
                        id_cliente: result.insertId,
                        mensagem: 'Cliente cadastrado com sucesso'
                    });
                }
            );
        }

        if (id_conta) {
            return inserirCliente(id_conta);
        }

        const numeroConta = `C-${Date.now()}`;

        connection.query(
            'INSERT INTO conta (numero) VALUES (?)',
            [numeroConta],
            (err, result) => {
                if (err) {
                    return res.status(500).json({
                        erro: 'Erro ao criar conta do cliente'
                    });
                }

                inserirCliente(result.insertId);
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
    permitir('ADMIN', 'LOJISTA'),
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
            LEFT JOIN conta c ON c.id_conta = l.id_conta
            ORDER BY l.id_loja DESC
        `;

        connection.query(sql, (err, results) => {
            if (err) {
                return res.status(500).json({
                    erro: 'Erro ao buscar lojas'
                });
            }

            res.json(results);
        });
    }
);

app.post(
    '/api/lojas',
    autenticar,
    permitir('ADMIN', 'LOJISTA'),
    (req, res) => {
        const {
            nome,
            tipo,
            endereco,
            id_conta
        } = req.body;

        if (!nome) {
            return res.status(400).json({
                erro: 'Nome da loja é obrigatório'
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
                            erro: 'Erro ao cadastrar loja'
                        });
                    }

                    res.status(201).json({
                        id_loja: result.insertId,
                        mensagem: 'Loja cadastrada com sucesso'
                    });
                }
            );
        }

        if (id_conta) {
            return inserirLoja(id_conta);
        }

        const numeroConta = `L-${Date.now()}`;

        connection.query(
            'INSERT INTO conta (numero) VALUES (?)',
            [numeroConta],
            (err, result) => {
                if (err) {
                    return res.status(500).json({
                        erro: 'Erro ao criar conta da loja'
                    });
                }

                inserirLoja(result.insertId);
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
    permitir('ADMIN', 'LOJISTA'),
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
                        erro: 'Erro ao buscar categorias'
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
    permitir('ADMIN', 'LOJISTA'),
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
            'INSERT INTO categoria (nome, descricao) VALUES (?, ?)',
            [nome, descricao || null],
            (err, result) => {
                if (err) {
                    return res.status(500).json({
                        erro: 'Erro ao cadastrar categoria'
                    });
                }

                res.status(201).json({
                    id_categoria: result.insertId,
                    mensagem: 'Categoria cadastrada com sucesso'
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
    permitir('ADMIN'),
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
                        erro: 'Erro ao buscar fornecedores'
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
                erro: 'Razão social e CNPJ são obrigatórios'
            });
        }

        connection.query(
            `INSERT INTO fornecedor
            (razao_social, cnpj, email, telefone)
            VALUES (?, ?, ?, ?)`,
            [
                razao_social,
                cnpj,
                email || null,
                telefone || null
            ],
            (err, result) => {
                if (err) {
                    return res.status(400).json({
                        erro: err.code === 'ER_DUP_ENTRY'
                            ? 'CNPJ já cadastrado'
                            : 'Erro ao cadastrar fornecedor'
                    });
                }

                res.status(201).json({
                    id_fornecedor: result.insertId,
                    mensagem: 'Fornecedor cadastrado com sucesso'
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
    permitir('ADMIN', 'OPERADOR', 'VENDEDOR', 'LOJISTA', 'CLIENTE'),
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
                COALESCE(SUM(e.quantidade), 0) AS estoque,
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

        connection.query(sql, (err, results) => {
            if (err) {
                return res.status(500).json({
                    erro: 'Erro ao buscar produtos'
                });
            }

            res.json(results);
        });
    }
);

app.post(
    '/api/produtos',
    autenticar,
    permitir('ADMIN', 'LOJISTA'),
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

        if (!nome || preco === undefined || !categoria || !loja) {
            return res.status(400).json({
                erro: 'Preencha os campos obrigatórios'
            });
        }

        connection.beginTransaction((err) => {
            if (err) {
                return res.status(500).json({
                    erro: 'Erro ao iniciar cadastro'
                });
            }

            connection.query(
                `INSERT INTO produto
                (nome, tendencia, novidade, preco, id_categoria, id_loja)
                VALUES (?, ?, ?, ?, ?, ?)`,
                [
                    nome,
                    tendencia ? 1 : 0,
                    novidade ? 1 : 0,
                    preco,
                    categoria,
                    loja
                ],
                (err, result) => {
                    if (err) {
                        return connection.rollback(() => {
                            res.status(400).json({
                                erro: 'Erro ao cadastrar produto'
                            });
                        });
                    }

                    const idProduto = result.insertId;

                    if (!fornecedor || estoque === undefined) {
                        return connection.commit((err) => {
                            if (err) {
                                return connection.rollback(() => {
                                    res.status(500).json({
                                        erro: 'Erro ao finalizar cadastro'
                                    });
                                });
                            }

                            res.status(201).json({
                                id_produto: idProduto,
                                mensagem: 'Produto cadastrado com sucesso'
                            });
                        });
                    }

                    connection.query(
                        `INSERT INTO estoque
                        (id_produto, id_fornecedor, quantidade)
                        VALUES (?, ?, ?)`,
                        [
                            idProduto,
                            fornecedor,
                            Number(estoque) || 0
                        ],
                        (err) => {
                            if (err) {
                                return connection.rollback(() => {
                                    res.status(400).json({
                                        erro: 'Produto criado, mas houve erro ao cadastrar estoque'
                                    });
                                });
                            }

                            connection.commit((err) => {
                                if (err) {
                                    return connection.rollback(() => {
                                        res.status(500).json({
                                            erro: 'Erro ao finalizar cadastro'
                                        });
                                    });
                                }

                                res.status(201).json({
                                    id_produto: idProduto,
                                    mensagem: 'Produto cadastrado com sucesso'
                                });
                            });
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
    permitir('ADMIN', 'OPERADOR', 'LOJISTA'),
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
            LEFT JOIN produto p
                ON p.id_produto = e.id_produto
            LEFT JOIN fornecedor f
                ON f.id_fornecedor = e.id_fornecedor
            ORDER BY e.id_estoque DESC
        `;

        connection.query(sql, (err, results) => {
            if (err) {
                return res.status(500).json({
                    erro: 'Erro ao buscar estoque'
                });
            }

            res.json(results);
        });
    }
);

app.post(
    '/api/estoque',
    autenticar,
    permitir('ADMIN', 'OPERADOR', 'LOJISTA'),
    (req, res) => {
        const {
            produto,
            fornecedor,
            quantidade
        } = req.body;

        if (!produto || !fornecedor || quantidade === undefined) {
            return res.status(400).json({
                erro: 'Preencha os campos obrigatórios'
            });
        }

        connection.query(
            `INSERT INTO estoque
            (id_produto, id_fornecedor, quantidade)
            VALUES (?, ?, ?)`,
            [
                produto,
                fornecedor,
                quantidade
            ],
            (err, result) => {
                if (err) {
                    return res.status(400).json({
                        erro: 'Erro ao cadastrar estoque'
                    });
                }

                res.status(201).json({
                    id_estoque: result.insertId,
                    mensagem: 'Estoque cadastrado com sucesso'
                });
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
    permitir('ADMIN', 'OPERADOR', 'VENDEDOR', 'LOJISTA'),
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
            LEFT JOIN cliente c
                ON c.id_cliente = v.id_cliente
            LEFT JOIN loja l
                ON l.id_loja = v.id_loja
            ORDER BY v.id_venda DESC
        `;

        connection.query(sql, (err, results) => {
            if (err) {
                return res.status(500).json({
                    erro: 'Erro ao buscar vendas'
                });
            }

            res.json(results);
        });
    }
);

app.post(
    '/api/vendas',
    autenticar,
    permitir('ADMIN', 'OPERADOR', 'VENDEDOR', 'LOJISTA'),
    (req, res) => {
        const {
            cliente,
            loja,
            canal,
            forma,
            valorPago,
            itens
        } = req.body;

        if (!cliente || !loja || !canal) {
            return res.status(400).json({
                erro: 'Preencha os campos obrigatórios'
            });
        }

        if (!Array.isArray(itens) || !itens.length) {
            return res.status(400).json({
                erro: 'Adicione pelo menos um produto'
            });
        }

        connection.beginTransaction((err) => {
            if (err) {
                return res.status(500).json({
                    erro: 'Erro ao iniciar venda'
                });
            }

            const ids = itens.map(item => Number(item.produto));

            connection.query(
                `SELECT
                    p.id_produto,
                    p.preco,
                    COALESCE(SUM(e.quantidade), 0) AS estoque,
                    MIN(e.id_estoque) AS id_estoque
                 FROM produto p
                 LEFT JOIN estoque e
                    ON e.id_produto = p.id_produto
                 WHERE p.id_produto IN (?)
                 GROUP BY p.id_produto, p.preco`,
                [ids],
                (err, produtosBanco) => {
                    if (err) {
                        return connection.rollback(() => {
                            res.status(500).json({
                                erro: 'Erro ao consultar produtos'
                            });
                        });
                    }

                    let total = 0;
                    const itensVenda = [];

                    for (const item of itens) {
                        const produto = produtosBanco.find(
                            p => Number(p.id_produto) === Number(item.produto)
                        );

                        const quantidade = Number(item.quantidade);

                        if (!produto) {
                            return connection.rollback(() => {
                                res.status(400).json({
                                    erro: 'Produto não encontrado'
                                });
                            });
                        }

                        if (quantidade <= 0) {
                            return connection.rollback(() => {
                                res.status(400).json({
                                    erro: 'Quantidade inválida'
                                });
                            });
                        }

                        if (Number(produto.estoque) < quantidade) {
                            return connection.rollback(() => {
                                res.status(400).json({
                                    erro: `Estoque insuficiente para o produto`
                                });
                            });
                        }

                        const subtotal =
                            Number(produto.preco) * quantidade;

                        total += subtotal;

                        itensVenda.push({
                            produto: produto.id_produto,
                            estoque: produto.id_estoque,
                            quantidade,
                            preco: produto.preco
                        });
                    }

                    connection.query(
                        `INSERT INTO venda
                        (valor_total, canal, status, id_cliente, id_loja)
                        VALUES (?, ?, 'ABERTA', ?, ?)`,
                        [
                            total,
                            canal,
                            cliente,
                            loja
                        ],
                        (err, vendaResult) => {
                            if (err) {
                                return connection.rollback(() => {
                                    res.status(400).json({
                                        erro: 'Erro ao cadastrar venda'
                                    });
                                });
                            }

                            const idVenda = vendaResult.insertId;

                            let processados = 0;

                            function finalizar() {
                                const pago = Number(valorPago || 0);
                                const status =
                                    pago >= total
                                        ? 'CONCLUIDO'
                                        : 'ABERTA';

                                connection.query(
                                    `UPDATE venda
                                     SET status = ?
                                     WHERE id_venda = ?`,
                                    [status, idVenda],
                                    (err) => {
                                        if (err) {
                                            return connection.rollback(() => {
                                                res.status(500).json({
                                                    erro: 'Erro ao atualizar venda'
                                                });
                                            });
                                        }

                                        if (pago > 0 && forma) {
                                            connection.query(
                                                `INSERT INTO pagamento
                                                (id_venda, forma, valor, status)
                                                VALUES (?, ?, ?, 'CONCLUIDO')`,
                                                [
                                                    idVenda,
                                                    forma,
                                                    Math.min(pago, total)
                                                ],
                                                (err) => {
                                                    if (err) {
                                                        return connection.rollback(() => {
                                                            res.status(500).json({
                                                                erro: 'Erro ao registrar pagamento'
                                                            });
                                                        });
                                                    }

                                                    concluir();
                                                }
                                            );
                                        } else {
                                            concluir();
                                        }
                                    }
                                );
                            }

                            function concluir() {
                                connection.commit((err) => {
                                    if (err) {
                                        return connection.rollback(() => {
                                            res.status(500).json({
                                                erro: 'Erro ao finalizar venda'
                                            });
                                        });
                                    }

                                    res.status(201).json({
                                        id: idVenda,
                                        id_venda: idVenda,
                                        total,
                                        mensagem: 'Venda realizada com sucesso'
                                    });
                                });
                            }

                            if (!itensVenda.length) {
                                return finalizar();
                            }

                            itensVenda.forEach(item => {
                                connection.query(
                                    `INSERT INTO item_venda
                                    (id_venda, id_produto, id_estoque, quantidade, preco_unitario)
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
                                            return connection.rollback(() => {
                                                res.status(500).json({
                                                    erro: 'Erro ao registrar item da venda'
                                                });
                                            });
                                        }

                                        connection.query(
                                            `UPDATE estoque
                                             SET quantidade = quantidade - ?
                                             WHERE id_estoque = ?`,
                                            [
                                                item.quantidade,
                                                item.estoque
                                            ],
                                            (err) => {
                                                if (err) {
                                                    return connection.rollback(() => {
                                                        res.status(500).json({
                                                            erro: 'Erro ao atualizar estoque'
                                                        });
                                                    });
                                                }

                                                processados++;

                                                if (processados === itensVenda.length) {
                                                    finalizar();
                                                }
                                            }
                                        );
                                    }
                                );
                            });
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
    permitir('ADMIN', 'OPERADOR'),
    (req, res) => {
        const sql = `
            SELECT
                v.id_venda AS id,
                c.nome AS cliente,
                v.valor_total AS total,
                COALESCE(SUM(p.valor), 0) AS pago,
                v.valor_total - COALESCE(SUM(p.valor), 0) AS restante
            FROM venda v
            LEFT JOIN cliente c
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

        connection.query(sql, (err, results) => {
            if (err) {
                return res.status(500).json({
                    erro: 'Erro ao buscar pendências'
                });
            }

            res.json(results);
        });
    }
);


/* =========================
   PAGAMENTOS
========================= */

app.get(
    '/api/pagamentos',
    autenticar,
    permitir('ADMIN', 'OPERADOR'),
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

        connection.query(sql, (err, results) => {
            if (err) {
                return res.status(500).json({
                    erro: 'Erro ao buscar pagamentos'
                });
            }

            res.json(results);
        });
    }
);

app.post(
    '/api/pagamentos',
    autenticar,
    permitir('ADMIN', 'OPERADOR'),
    (req, res) => {
        const {
            venda,
            forma,
            valor
        } = req.body;

        if (!venda || !forma || valor === undefined) {
            return res.status(400).json({
                erro: 'Preencha os campos obrigatórios'
            });
        }

        connection.query(
            `SELECT
                valor_total,
                COALESCE(
                    (SELECT SUM(valor)
                     FROM pagamento
                     WHERE id_venda = ?),
                    0
                ) AS pago
             FROM venda
             WHERE id_venda = ?`,
            [venda, venda],
            (err, results) => {
                if (err || !results.length) {
                    return res.status(400).json({
                        erro: 'Venda não encontrada'
                    });
                }

                const total = Number(results[0].valor_total);
                const pagoAtual = Number(results[0].pago);
                const valorPagamento = Number(valor);

                if (valorPagamento <= 0) {
                    return res.status(400).json({
                        erro: 'Valor do pagamento inválido'
                    });
                }

                if (pagoAtual + valorPagamento > total) {
                    return res.status(400).json({
                        erro: 'O pagamento não pode ser maior que o valor restante'
                    });
                }

                connection.query(
                    `INSERT INTO pagamento
                    (id_venda, forma, valor, status)
                    VALUES (?, ?, ?, 'CONCLUIDO')`,
                    [
                        venda,
                        forma,
                        valorPagamento
                    ],
                    (err, result) => {
                        if (err) {
                            return res.status(400).json({
                                erro: 'Erro ao cadastrar pagamento'
                            });
                        }

                        const novoPago = pagoAtual + valorPagamento;

                        if (novoPago >= total) {
                            connection.query(
                                `UPDATE venda
                                 SET status = 'CONCLUIDO'
                                 WHERE id_venda = ?`,
                                [venda],
                                () => {}
                            );
                        }

                        res.status(201).json({
                            id_pagamento: result.insertId,
                            mensagem: 'Pagamento registrado com sucesso'
                        });
                    }
                );
            }
        );
    }
);


/* =========================
   EXTRATO
========================= */

app.get(
    '/api/clientes/:id/extrato',
    autenticar,
    (req, res) => {
        const idCliente =
            req.params.id === 'me'
                ? req.usuario.id_cliente
                : Number(req.params.id);

        if (!idCliente) {
            return res.status(400).json({
                erro: 'Cliente inválido'
            });
        }

        if (
            req.usuario.perfil === 'CLIENTE' &&
            Number(req.usuario.id_cliente) !== Number(idCliente)
        ) {
            return res.status(403).json({
                erro: 'Você só pode consultar seu próprio extrato'
            });
        }

        const sqlConta = `
            SELECT
                c.id_cliente,
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
                if (err || !conta.length) {
                    return res.status(404).json({
                        erro: 'Cliente não encontrado'
                    });
                }

                const sqlVendas = `
                    SELECT
                        v.id_venda AS id,
                        v.data,
                        l.nome AS loja,
                        v.valor_total AS total,
                        COALESCE(SUM(p.valor), 0) AS pago,
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
                                erro: 'Erro ao buscar extrato'
                            });
                        }

                        res.json({
                            conta: {
                                numero: conta[0].numero,
                                saldo: conta[0].saldo
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
                        erro: 'Erro ao buscar suas compras'
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
                    WHEN cl.id_cliente IS NOT NULL THEN 'Cliente'
                    WHEN l.id_loja IS NOT NULL THEN 'Loja'
                    ELSE 'Conta'
                END AS tipo,
                COALESCE(cl.nome, l.nome, '-') AS nome,
                c.numero,
                c.saldo
            FROM conta c
            LEFT JOIN cliente cl
                ON cl.id_conta = c.id_conta
            LEFT JOIN loja l
                ON l.id_conta = c.id_conta
            ORDER BY c.id_conta DESC
        `;

        connection.query(sql, (err, results) => {
            if (err) {
                return res.status(500).json({
                    erro: 'Erro ao buscar contas'
                });
            }

            res.json(results);
        });
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
                COALESCE(SUM(valor_total), 0) AS faturamento
             FROM venda`,
            (err, vendaResult) => {
                if (err) {
                    return res.status(500).json({
                        erro: 'Erro ao gerar relatório'
                    });
                }

                dados.vendas = Number(vendaResult[0].vendas);
                dados.faturamento = Number(vendaResult[0].faturamento);
                dados.ticket =
                    dados.vendas > 0
                        ? dados.faturamento / dados.vendas
                        : 0;

                connection.query(
                    `SELECT
                        COALESCE(SUM(valor), 0) AS recebido
                     FROM pagamento`,
                    (err, recebidoResult) => {
                        if (err) {
                            return res.status(500).json({
                                erro: 'Erro ao gerar relatório'
                            });
                        }

                        dados.recebido =
                            Number(recebidoResult[0].recebido);

                        connection.query(
                            `SELECT
                                p.nome,
                                SUM(iv.quantidade) AS qtd,
                                SUM(iv.quantidade * iv.preco_unitario) AS total
                             FROM item_venda iv
                             INNER JOIN produto p
                                ON p.id_produto = iv.id_produto
                             GROUP BY p.id_produto, p.nome
                             ORDER BY qtd DESC
                             LIMIT 10`,
                            (err, topProdutos) => {
                                if (err) {
                                    return res.status(500).json({
                                        erro: 'Erro ao gerar relatório'
                                    });
                                }

                                dados.topProdutos = topProdutos;

                                connection.query(
                                    `SELECT
                                        l.nome,
                                        COUNT(v.id_venda) AS vendas,
                                        COALESCE(SUM(v.valor_total), 0) AS total
                                     FROM venda v
                                     INNER JOIN loja l
                                        ON l.id_loja = v.id_loja
                                     GROUP BY l.id_loja, l.nome
                                     ORDER BY total DESC`,
                                    (err, porLoja) => {
                                        if (err) {
                                            return res.status(500).json({
                                                erro: 'Erro ao gerar relatório'
                                            });
                                        }

                                        dados.porLoja = porLoja;

                                        connection.query(
                                            `SELECT
                                                forma,
                                                COALESCE(SUM(valor), 0) AS total
                                             FROM pagamento
                                             GROUP BY forma
                                             ORDER BY total DESC`,
                                            (err, porForma) => {
                                                if (err) {
                                                    return res.status(500).json({
                                                        erro: 'Erro ao gerar relatório'
                                                    });
                                                }

                                                dados.porForma = porForma;

                                                res.json(dados);
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
   INICIAR SERVIDOR
========================= */

app.listen(port, () => {
    console.log(`Servidor rodando em http://localhost:${port}`);
});