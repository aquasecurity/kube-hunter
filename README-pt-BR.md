![kube-hunter](https://github.com/aquasecurity/kube-hunter/blob/master/kube-hunter.png)

[![Estado da construção](https://travis-ci.org/aquasecurity/kube-hunter.svg?branch=master)]](https://travis-ci.org/aquasecurity/kube-hunter)

Kube-hunter caça fraquezas de segurança em aglomerados de Kubernetes. A ferramenta foi desenvolvida para aumentar a conscientização e a visibilidade de questões de segurança em ambientes Kubernetes. **Você NÃO deve executar o kube-hunter em um cluster Kubernetes que você não possui!

**Run kube-hunter***: kube-hunter está disponível como um container (aquasec/kube-hunter), e nós também oferecemos um web site em [kube-hunter.aquasec.com] (https://kube-hunter.aquasec.com) onde você pode se registrar online para receber um token permitindo que você veja e compartilhe os resultados online. Você também pode executar o código Python você mesmo como descrito abaixo.

Contribua****: Agradecemos contribuições, especialmente novos módulos de caçadores que realizam testes adicionais. Se você gostaria de desenvolver seus próprios módulos, por favor leia [Guidelines For Developing Your First kube-hunter Module](src/README.md).

[![kube-hunter demo video](https://github.com/aquasecurity/kube-hunter/blob/master/kube-hunter-screenshot.png)](https://youtu.be/s2-6rTkH8a8?t=57s)

## Caçando

### Onde é que devo correr kube-hunter?
Execute o kube-hunter em qualquer máquina (incluindo o seu laptop), selecione Verificação remota e forneça o endereço IP ou nome de domínio do seu cluster Kubernetes. Isso lhe dará uma visão de olhos de atacantes da sua configuração do Kubernetes.

Você pode executar o kube-hunter diretamente em uma máquina no cluster e selecionar a opção de sondar todas as interfaces de rede local.

Você também pode executar o kube-hunter em um pod dentro do cluster. Isso fornece uma indicação de quão exposto seu cluster estaria no caso de um dos seus pods de aplicativos ser comprometido (por meio de uma vulnerabilidade de software, por exemplo).

### Opções de varredura

Primeiro verifique o **[pré-requisitos](#prerequisites)**

Por padrão, o kube-hunter abrirá uma sessão interativa, na qual você poderá selecionar uma das seguintes opções de verificação. Você também pode especificar a opção de verificação manualmente a partir da linha de comando. Estas são as suas opções:

1. Verificação remota****
Para especificar máquinas remotas para caça, selecione a opção 1 ou use a opção `--remote`. Exemplo:
`./kube-hunter.py --remote some.node.com`

2. **Digitalização de interfaces
Para especificar a digitalização da interface, você pode usar a opção `--interface`. (isto irá verificar todas as interfaces de rede da máquina) Exemplo:
`./kube-hunter.py --interface`

3. **Varredura da rede***
Para especificar um CIDR específico para verificação, use a opção `--cidr`. Exemplo:
`./kube-hunter.py --cidr 192.168.0.0.0/24`

### Caça Ativa

A caça ativa é uma opção na qual o kube-hunter explorará vulnerabilidades encontradas, a fim de explorar outras vulnerabilidades.
A principal diferença entre a caça normal e a caça ativa é que uma caça normal nunca mudará o estado do cluster, enquanto a caça ativa pode potencialmente fazer operações de mudança de estado no cluster, **o que pode ser prejudicial***.

Por padrão, o kube-hunter não faz caça ativa. Para caçar ativamente um cluster, use a flag `--active`. Exemplo:
`./kube-hunter.py --remote some.domain.com --active`

### Lista de testes
Você pode ver a lista de testes com a opção `--list`: Exemplo:
`./kube-hunter.py --list`

Ver testes de caça activa e passiva:
`./kube-hunter.py --list --active`

### Mapeamento de nós 
Para ver apenas um mapeamento de sua rede de nós, rode com a opção `--mapping`. Exemplo:
`./kube-hunter.py --cidr 192.168.0.0.0/24 --mapping`
Isso resultará em todos os nós do Kubernetes que o kube-hunter encontrou.

### Saída
Para controlar o log, você pode especificar um nível de log, usando a opção `--log`. Exemplo:
`./kube-hunter.py --active --log WARNING''.
Os níveis de registo disponíveis são:

* DEBUG
* INFO (padrão)
* ADVERTÊNCIA

### A despachar...
Por padrão, o relatório será enviado para `stdout`, mas você pode especificar métodos diferentes, usando a opção `--dispatch`. Exemplo:
`./kube-hunter.py --report json --dispatch http`
Os métodos de expedição disponíveis são:

* stdout (padrão)
* http (para configurar, defina as seguintes variáveis de ambiente:) 
    * KUBEHUNTER_HTTP_DISPATCH_URL (padrão: https://localhost)
    * KUBEHUNTER_HTTP_DISPATCH_METHOD (valores propostos para: POST)

## Implantação
Há três métodos para implementar o kube-hunter:

### Na máquina

Você pode executar o código python do kube-hunter diretamente na sua máquina.
#### Pré-requisitos

Você precisará do seguinte instalado:
* python 3.x
* pip

Clonar o repositório:
~~~
git clone https://github.com/aquasecurity/kube-hunter.git
~~~

Instalar dependências do módulo. (Você pode preferir fazer isso em um [Ambiente Virtual] (https://packaging.python.org/guides/installing-using-pip-and-virtual-environments/))
~~~
cd ./kube-hunter
pip install -r requisitos.txt
~~~

Foge:
`./kube-hunter.py`

Se você quiser usar pyinstaller/py2exe você precisa primeiro executar o script install_imports.py.
### Container
Aqua Security mantém uma versão contentorizada do kube-hunter em `aquasec/kube-hunter`. Este container inclui este código fonte, mais um plugin adicional (código fechado) para reportar resultados em um relatório que pode ser visto em [kube-hunter.aquasec.com](https://kube-hunter.aquasec.com). Por favor, note que a execução do container `aquasec/kube-hunter` e o carregamento de dados de relatórios estão sujeitos a [termos e condições] (https://kube-hunter.aquasec.com/eula.html).

O arquivo Dockerfile neste repositório permite que você construa uma versão em container sem o plugin de relatórios.

Se você rodar o container kube-hunter com a rede host, ele será capaz de testar todas as interfaces no host:

`docker run -it --it --rm --network host aquasec/kube-hunter`

Nota para Docker para Mac/Windows:_ Esteja ciente de que o "host" para Docker para Mac ou Windows é a VM na qual o Docker executa containers. Portanto, especificar `--network host` permite que o kube-hunter acesse as interfaces de rede dessa VM, ao invés daquelas de sua máquina.
Por padrão o kube-hunter roda em modo interativo. Você também pode especificar a opção de rastreamento com os parâmetros descritos acima, por exemplo

`docker run --rm aquasec/kube-hunter --cidr 192.168.0.0.0/24`

### Pod
Essa opção permite que você descubra o que a execução de um contêiner malicioso pode fazer/descobrir em seu cluster. Isso dá uma perspectiva sobre o que um atacante poderia fazer se fosse capaz de comprometer um pod, talvez por meio de uma vulnerabilidade de software. Isso pode revelar significativamente mais vulnerabilidades.

O arquivo `job.yaml` define um Job que rodará o kube-hunter em um pod, usando as configurações padrão de acesso ao pod Kubernetes.
* Execute o job com `kubectl create` com esse arquivo yaml.
* Encontre o nome do pod com `kubectl describe job kube-hunter`.
* Veja os resultados do teste com `kubectl logs <pod name>`
