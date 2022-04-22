# OWASP
## Introdução
- A OWASP é uma organização internacional, sem fins lucrativos. O foco é segurança em aplicações.
- Tem como objetivo dar visibilidade à necessidade de segurança em apps Web, além de melhorar a segurança de software de um modo geral.
- Ela está presente em vários locais através da denominação de capítulos. Por exemplo, capítulo OWASP Brasília.

## OWASP TOP 10 - 2021
### Introdução 
- É um documento feito por especialistas.
- Lista os 10 riscos mais críticos à segurança - apps Web. OS MAIS CRÍTICOS, Não todos!
- Esses riscos são listados por ordem de importância.
- Os riscos são revisados a cada 3 anos, em média.

### TOP 10 - 2017 x TOP 10 - 2021 <!-- fold -->
- [Diferenças](https://owasp.org/Top10/#whats-changed-in-the-top-10-for-2021)

### A01:2021 Broken Access Control <!-- fold -->

#### Descrição
- Diz respeito à implementação falha/inadequada de controle de acesso, durante o desenvolvimento.
- Possui alta ocorrência em APIs.

#### Constatações comuns
- Vazamento, modificação e exclusão de dados.
- Violação do privilégio mínimo/negação por padrão.
- App não verifica alterações forçadas em Urls.
- App permite visualização/modificação de contas de outros usuários.
- Permite referenciar, de forma não segura, diretamente objetos.
- Ausência de controle aos métodos *POST*, *PUT* e *DELETE*.
- Modificação de Tokens de acesso ou Cookies (elevação de privilégios).
- Configuração falha de *CORS* - [Doc](https://developer.mozilla.org/pt-BR/docs/Web/HTTP/CORS).
- [Exemplos](https://owasp.org/Top10/A01_2021-Broken_Access_Control/#example-attack-scenarios)

#### Prevenção
- Sempre negar por padrão, a menos que o recurso tenha que ser público.
- Utilizar minimamente *CORS*.
- Sempre verificar se o usuário tem permissão para determinada operação (criar, ler, apagar, alterar). 
- Evitar que arquivos de *SVC* (.git) e arquivos de backup não estejam públicos.
- Sempre registre falhas de controle de acesso, notificando responsáveis.
- Use mecanimos de rate limit em APIs. Evita-se ferramentas automatizadas.
- Invalide sessões após logout do usuário.

#### [Documentação](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) 

### A02:2021 Cryptographic Failures <!-- fold -->
#### Descrição
- Relacionada à quebra de sigilo de dados (em repouso/em trânsito).
- Resultado de um algoritmo fraco.
- Na versão anterior era a ***A3:2017 Sensitive Data Exposure***.

#### Constatações comuns
- Trânsito/armazenamento de dados em texto plano.
- Utilização de protocolos inseguros (*HTTP*, *SMTP*, *FTP*, etc).
- Uso de algoritmos de criptografia antigos/fracos.
- Chaves criptográticas fracas.
- Não forçar uso de protocolos seguros (ex.: *HTTP* -> *HTTPS*).
- Uso de hashes obsoletos (ex.: *MD5*, *SHA1*).
- [Exemplos](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/#example-attack-scenarios)

#### Prevenção
- Identificar todos os dados sensíveis que a app usa/manipula.
- Não armazenar dados sensíveis sem necessidade.
- Utilizar criptografia nos dados (em repouso ou trânsito).
- Usar *TLS* nas informações em trânsito.
- Utilizar hashes fortes no armazenamento de senhas (*Argon2*, *bcrypt*, *scrypt* ou *PBKDF2*).
- Implementar *Salt* como camada adicional, a fim de evitar ataques rainbow tables.
- Evitar uso de hashes inseguros (*MD5* ou *SHA1*).
- Verificação de forma independente as a efetividade das configurações.

#### [Documentação](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)

### A03:2021 Injection <!-- fold -->
#### Descrição
- A app permite que o usuário entre com códigos/comandos com sucesso (*SQL*, *Shell*, *LDAP*, etc).
- Ainda há muitas apps vulneráveis, ainda que seja simples evitar.
- A categoria ***A7:2017 Cross-Site Scripting (XSS)*** foi "mergeada" nessa categoria.

#### Constatações comuns
- Falta de validação da entrada do usuário.
- Consultas em banco não parametrizadas.
- Uso de dados maliciosos em parâmetros de pesquisa de um *ORM*.
- Uso de dados maliciosos (direta/concatenada) em consultas *SQL*.
- [Exemplos](https://owasp.org/Top10/A03_2021-Injection/#example-attack-scenarios)

#### Prevenção
- Prefirir o uso de *ORM - Object Relational Mapping*. Ex.: *SQLAlchemy*.
- Valide sempre a entrada do usuário com *whitelists* e *regex*.
- Utilize *LIMIT* e outros controles *SQL*, dimuindo o impacto de *SQL Injection* com sucesso.
- Codificar as saídas de entradas de usuários, evitando *XSS*.

#### [Documentação](https://owasp.org/Top10/A03_2021-Injection/)

### A04:2021 Insecure Design <!-- fold -->
#### Descrição
- É uma categoria nova!
- Ampla abrangência focada em riscos relacionados às falhas de arquitetura.
- Design inseguro não é a mesma coisa que implementação com falha.
- Um design seguro, pode conter falhas de implementação.
- Um design inseguro não pode ser corrigido por implementação correta.

#### Constatações comuns
- Não modelagem de ameaças durante o desenvolvimento.
- Falta de padrões de design seguros e arquiteturas referenciais.
- Inexistência de comunicação entre os times de Dev e Sec.
- [Exemplos](https://owasp.org/Top10/A04_2021-Insecure_Design/#example-attack-scenarios)

#### Prevenção
- Estabelecer um ciclo de vida de desenvolvimento seguro. [link1](https://blog.convisoappsec.com/secure-software-development-lifecycle-s-sdlc-o-que-e/) - [link2](https://www.microsoft.com/en-us/securityengineering/sdl)
- Utilizar *libs* seguras para operações com usuários.
- Usar modelagem de ameaças, a fim de indentificar pontos vulneráveis na app.
- Escreva testes unitários.
- Incorpore os conceitos: *Secure by Design* e *Privacy by Design*.

#### [Documentação](https://owasp.org/Top10/A04_2021-Insecure_Design/)

### A05:2021 Security Misconfiguration <!-- fold -->
#### Descrição
- Erros/falta de configuração.
- Configuração padrão é colocada em produção, juntamente com a ausência de *hardening*.
- A ***A4:2017 XML External Entities (XXE)*** agora faz parte dessa categoria.

#### Constatações comuns
- Presença de elementos desnecessários (portas abertas, serviços, páginas, etc).
- Falta de *hardening* nos servidores.
- Utilização de contas/senhas padrões.
- Exibir erros com detalhes ao usuários.
- Exposição de *stack traces*.
- Recursos de segurança desabilitados ou mal configurados.
- Exibir informações do cabeçalho Server *HTTP*.
- Bucket de objetos públicos (*Cloud*).
- [Exemplos](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/#example-attack-scenarios)

#### Prevenção
- Executar o *hardening* nos servidores.
- Minimizar o uso de recursos desnecessários.
- Remover ou mesmo nem instalar recursos não utilizados pelas apps ou *frameworks*.
- Validar todos os patches de segurança em ambiente controlado, antes de ir para prd.
- Minimizar exposição informações nos cabeçalhos e *banners*.
- Automatizar a implementação de medidas de segurança nos servidores.
#### [Documentação](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)

### A06:2021 Vulnerable and Outdated Components <!-- fold -->
#### Descrição
- Uso de componentes na app desatualizados e/ou que possuam vulnerebilidades.
- Ocorre quando se confiar "cegamente" em códigos de terceiros.
- Quando se tem falta de atualizações e processo automatizado de busca de *vulns* nos componentes.

#### Constatações comuns
- Time de dev não conhece as versões de todos os componentes usados na app.
- Os componentes incluem: *SGBD*, *S.O.*, *Webserver*, *libs* e dependências.
- Falta de processo *scan* de *vulns*, executado frequentemente.
- Utilização de componentes que não são mais mantidos.
- Time de dev não atualiza os componentes em tempo hábil.
- [Exemplos](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/#example-attack-scenarios)

#### Prevenção
- Utilizar alguma ferramenta de *SAST - Static application security testing* (Ex.: Sonar).
- Utilizar *OWASP Dependency-check*;
- Remover dependências não utilizadas, recursos, arquivos e docs desnecessários em prd.
- Possuir catálogo de todos os componentes/dependências da app.  
    - O catálogo deve possuir versões e licenças.
    - O catálogo deve ser tanto server-side como client-side.
- Realizar procedimento de *SCA* ([Software Composition Analysis](https://www.nova8.com.br/2020/12/03/o-que-e-sca-software-composition-analysis/)) frequentemente.
    - *OWASP Dependecy-check* ajuda!
- Sempre: obter os componentes de fontes seguras e oficiais.  
    - Verique a integridade (função *hash*), se possível.
- Monitorar bibliotecas
    - Não mais mantidas ou
    - Sem disponibilização de patches de segurança para versões antigas.

#### [Documentação](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)

### A07:2021 Identification and Authentication Failures <!-- fold -->
#### Descrição
- É a antiga categoria *Broken Authentication*.
- Quando uma App falha no processo de confirmação de identidade e autorização do usuário.

#### Constatações comuns
- Ocorre quando se opta por construir a própria autenticação do zero.
- A app expõe usuários válidos, facilitando ataques direcionados.
- App permite uso de senhas fracas/conhecidas.
- App usa mecanimos inseguros para recuperação de senha (Ex.: perguntas e respostas).
- Armazenagem de senhas
    - de forma insegura (Ex.: texto plano)
    - uso de hashes fracos.
- Não uso de *2FA* ou *MFA*.
- Exposição de *tokens* de sessão em urls ou em logs.
- Reuso de *tokens* de sessão.
- Ausência de validação de *ID* de sessão.
- [Exemplos](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/#example-attack-scenarios)

#### Prevenção
- Não reinvente a roda: Utilize *libs* de autenticação.
    - Use *libs* reconhecidamente seguras.
- Abuse de mecanismos de *2FA* e *MFA*. Muitas invasões poderiam ter sido evitadas apenas com isso.
- Mude sempre as credenciais *default* em ambientes de prd.
- Use rotinas de verificação de senhas fracas durante o processo de criação/edição do usuário.
- Exija requisitos mínimos de complexidade de senhas.
- Limite tentativas de *login* com falha.
- Guarde e analise os *logs* de tentativa de login falhos.

#### [Documentação](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)

### A08:2021 Software and Data Integrity Failures <!-- fold -->
#### Descrição
- Nova categoria.
- A ***A8:2017 Insecure Deserialization*** foi integrada nessa.
- Preocupa-se em falhas de softwares que comprometam a integridade dos dados.
- Com foco em fazer suposições:
    - relacionadas a atualizações de software
    - dados críticos e 
    - pipelines de *CI/CD* sem verificar a integridade.

#### Constatações comuns
- A App não verifica a assinatura de atualizações.
- Download de de código/executáveis sem validação de integridade.
- Desserialização de dados não confiáveis.
- Um atacante, por exemplo, consegue modificar dados vulneráveis à [desserialização insegura](https://rodolfomarianocy.medium.com/insecure-deserialization-entenda-e-explore-f9c31bba85a2).
- Confiar em *cookies* sem a devida validação/verificação de integridade. 
- [Exemplos](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/#example-attack-scenarios)

#### Prevenção
- Utilizar assinaturas digitais para validar/verificar se um software ou os dados não foram adulterados.
- Cientifique-se que gerenciadores de pacotes/dependências, como *npm* ou *mavem*, estão consumindo repositórios/fontes confiáveis.
- Use ferramentas como o *OWASP Dependency-check* para verificar se os componentes não possuem vulns conhecidas.
- Utilize um processo de reivisão de código, diminuindo a introdução de código malicioso na pipeline.
- Garanta que pipeline de *CI/CD* tenha segregação, configuração e controle de acesso adequados.
- A garantia acima visa a integridade do código que flui pelos processos de compilação e implantação.
- Realize o processo de desserialização apenas em dados assinados e confiáveis.

#### [Documentação](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)

### A09:2021 Security Logging and Monitoring Failures <!-- fold -->
#### Descrição
- É quando uma app falha no correto monitoramento e análise de *logs*.
- Anteriormente denominada de ***A10:2017-Insufficient Logging & Monitoring***.

#### Constatações comuns
- Sem o correto monitoramento e análise de logs, a detecção ataques em tempo hábil fica prejudicada.
- Ausência de eventos auditáveis de valor
    - *logins*
    - *logins* com falha
    - transações de alto valor
- Avisos e Erros geram logs inadequados ou sem clareza.
- Ausência de monitoramento para atividades suspeitas em logs de Apps e *APIs*.
- Armazenamento de *logs* apenas localmente.
- Testes de invasão varreduras automatizadas não disparam alertas.
- As Apps não conseguem detectar e alertar quando ocorrem ataques ativos em tempo real.
- [Exemplos](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/#example-attack-scenarios)

#### Prevenção
- As informações importantes devem ser registradas com o contexto do usuário, de modo a identificar contas suspeitas.
- Manter contas usadas em ataques desativadas até que seja feita a perícia forense.
- O ideal é que o formato dos logs consigam ser ingeridos por ferramentas auxiliares de análise, como a *Stack* *ELK*.
- Crie monitoramento e alertas eficazes, de modo que atividades suspeitas sejam detectadas/respondidas em tempo hábil.

#### [Documentação](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)

### A10:2021 Server-Side Request Forgery (SSRF) <!-- fold -->
#### Descrição 
- Nova categoria!
- Quando permite que um atacante force a App a realizar requests para domínios arbitrários.

#### Constatações comuns
- O atacante consegue interagir com o servidor alvo e obter informações sensíveis.
- A App não valida a busca por recursos remotos, não validando a *URL* fornecida pelo usuário.
- [Exemplos](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/#example-attack-scenarios)

#### Prevenção
- Segmentação de funcionalidade de acesso a recursos remotos em redes separadas, reduzindo o impacto do *SSRF*.
- Implementar política de "negar por padrão" em firewalls.
- Registrar todos os acessos com sucesso ou negados.
- Validar sempre os dados fornecidos pelo usuário.
- Utilize *whitelists* para validação de *URLs* fornecidas.

#### [Documentação](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)