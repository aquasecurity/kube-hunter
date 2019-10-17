! [kube-hunter] (https://github.com/aquasecurity/kube-hunter/blob/master/kube-hunter.png)

[! [Estado del edificio] (https://travis-ci.org/aquasecurity/kube-hunter.svg?branch=master)]] (https://travis-ci.org/aquasecurity/kube-hunter)

Kube-hunter caza las debilidades de seguridad en los grupos de Kubernetes. La herramienta está diseñada para aumentar la conciencia y la visibilidad de los problemas de seguridad en los entornos de Kubernetes. ** ¡NO debes ejecutar kube-hunter en un clúster de Kubernetes que no te pertenece!
** Ejecute kube-hunter ***: kube-hunter está disponible como contenedor (aquasec / kube-hunter), y también ofrecemos un sitio web en [kube-hunter.aquasec.com] (https: // kube- hunter.aquasec.com) donde puede registrarse en línea para recibir un token que le permite ver y compartir resultados en línea. También puede ejecutar el código Python usted mismo como se describe a continuación.

Contribuir ****: Apreciamos las contribuciones, especialmente los nuevos módulos de cazadores que realizan pruebas adicionales. Si desea desarrollar sus propios módulos, lea [Directrices para desarrollar su primer módulo kube-hunter] (src / README.md).

[! [video de demostración de kube-hunter] (https://github.com/aquasecurity/kube-hunter/blob/master/kube-hunter-screenshot.png)] (https://youtu.be/s2-6rTkH8a8? t = 57s)

## Caza

### ¿Dónde debo ejecutar kube-hunter?
Ejecute kube-hunter en cualquier máquina (incluida su computadora portátil), seleccione Exploración remota y proporcione la dirección IP o el nombre de dominio de su clúster Kubernetes. Esto le dará a los atacantes una vista de su configuración de Kubernetes.

Puede ejecutar kube-hunter directamente en una máquina en el clúster y seleccionar la opción para sondear todas las interfaces LAN.

También puedes ejecutar kube-hunter en un pod dentro del clúster. Esto proporciona una indicación de qué tan expuesto estaría su clúster si uno de los pods de su aplicación estuviera comprometido (a través de una vulnerabilidad de software, por ejemplo).

### Opciones de escaneo

Primero verifique los ** [requisitos previos] (# requisitos previos) **

Por defecto, kube-hunter abrirá una sesión interactiva en la que puede seleccionar una de las siguientes opciones de verificación. También puede especificar la opción de verificación manualmente desde la línea de comando. Estas son tus opciones:

1. Verificación remota ****
Para especificar máquinas de búsqueda remotas, seleccione la opción 1 o use la opción `--remote`. Ejemplo:
`./kube-hunter.py --remote some.node.com`

2. ** Escaneo de interfaz
Para especificar el escaneo de la interfaz, puede usar la opción `- interfaz`. (esto verificará todas las interfaces de red de la máquina) Ejemplo:
`./kube-hunter.py --interface`
3. ** Escaneo de red ***
Para especificar un CIDR específico para escanear, use la opción `--cidr`. Ejemplo:
`./kube-hunter.py --cidr 192.168.0.0.0 / 24`

### Caza activa

La caza activa es una opción en la que kube-hunter explotará las vulnerabilidades encontradas para explotar otras vulnerabilidades.
La principal diferencia entre la caza normal y la caza activa es que una caza normal nunca cambiará el estado del grupo, mientras que la caza activa puede realizar operaciones de cambio de grupo **, lo que puede ser perjudicial ***.

Por defecto, kube-hunter no realiza la caza activa. Para cazar activamente un clúster, use el indicador `--active`. Ejemplo:
`./kube-hunter.py --remote some.domain.com --active`

### Lista de prueba
Puede ver la lista de prueba con la opción `--list`: Ejemplo:
`./kube-hunter.py --list`

Ver pruebas de caza activas y pasivas:
`./kube-hunter.py --list --active`

### Asignación de nodos
Para ver solo una asignación de su red de nodos, ejecute la opción `--mapping`. Ejemplo:
`./kube-hunter.py --cidr 192.168.0.0.0 / 24 --mapeo`
Esto dará como resultado todos los nodos de Kubernetes que ha encontrado kube-hunter.

### Salir
Para controlar el registro, puede especificar un nivel de registro utilizando la opción `--log`. Ejemplo:
`./kube-hunter.py --active --log ADVERTENCIA ''.
Los niveles de registro disponibles son:
* DEPURACIÓN
* INFO (predeterminado)
* ADVERTENCIA
### Despachando ...
Por defecto, el informe se enviará a `stdout`, pero puede especificar diferentes métodos utilizando la opción` --dispatch`. Ejemplo:
`./kube-hunter.py --report json --dispatch http`
Los métodos de envío disponibles son:

* stdout (predeterminado)
* http (para establecer, establecer las siguientes variables de entorno :)
    * KUBEHUNTER_HTTP_DISPATCH_URL (predeterminado: https: // localhost)
    * KUBEHUNTER_HTTP_DISPATCH_METHOD (valores predeterminados para: POST)

## Implementación
Hay tres métodos para implementar kube-hunter:

### En la máquina

Puede ejecutar el código de python kube-hunter directamente desde su máquina.
#### Prerrequisitos

Necesitará lo siguiente instalado:
* python 3.x
* pip

Clonar el repositorio:
~~~
git clone https://github.com/aquasecurity/kube-hunter.git
~~~

Instalar dependencias de módulos. (Es posible que prefiera hacer esto en un [Entorno virtual] (https://packaging.python.org/guides/installi