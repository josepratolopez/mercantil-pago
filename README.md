# MercantilVE
Este es el repositorio de la colección de clases de consumo de APIs del Banco Mercantil de Venezuela para pago con tarjetas nacionales e internacionales.
## instanciación
```
$clientId: valor a ser enviado por header X-IBM-Client-Id (provisto por el banco)
$merchantId: ID de comercio (Merchant ID, provisto por el banco)
$claveCifrado: clave de cifrado (provisto por el banco)
$esProductivo: define el ambiente a ser utilizado por la API (0 si es ambiente de pruebas, 1 si es ambiente productivo)
```
```
$mercantil = new Pago(string $clientId, string  $merchantId, string $claveCifrado, bool $esProductivo);
```
## Datos POST del formulario de pago
No es necesario crear un formulario de pago, ya que este paquete contiene un método que devuelve un formulario de pago.

Boton de pago y formulario se obtiene mediante el llamado del método:
```
echo _buttonHtml(string $uriLogo, string $uriActionPost, double $monto)
```
Nota: parametro **$uriActionPost** se utiliza para indicar la URL del action del formulario, ese controlador debe existir en el servidor destino.
```
$_POST['card-num']: número de tarjeta
$_POST['card-type']: tipo de tarjeta ("tdc": débito o crédito nacional o internacional; "tdd": tarjeta de débito de banco mercantil (Venezuela))
$_POST['account-type']: tipo de cuenta (solo aparece en caso de que se seleccione "tarjeta de débito de banco mercantil" en el campo anterior. "CA": Cuenta de Ahorros; "CC": Cuenta Corriente)
$_POST['due-date']: vencimiento de tarjeta
$_POST['cvv']: CVV de la tarjeta
$_POST['user-firstname']: Nombre del usuario (no se envía mediante API de pago de Mercantil, puede ser usado para datos auxiliares a ser almacenados)
$_POST['user-lastname']: Apellido del usuario (no se envía mediante API de pago de Mercantil, puede ser usado para datos auxiliares a ser almacenados)
$_POST['user-docid']: documento de identidad del titular (Si es venezolano debe comenzar por el prefijo V, J, E, entre otros)
$_POST['user-email']: Email del usuario (no se envía mediante API de pago de Mercantil, puede ser usado para datos auxiliares a ser almacenados)
$_POST['amount']: Monto del pago (decimales deben ser expresados con un punto (.) en lugar de coma (,))
```
## métodos
Para iniciar un proceso de pago:
```
$response = $mercantil->payment(string $numeroTarjeta, string $fechaVencimientoTarjeta, string $cvvtarjeta, string $tipoTarjeta, string $cedulaCliente, string $direccionIpCliente, string $userAgentNavegador, string $idVenta, double $montoVenta, string $tipoCuenta = null);
```
Ejemplo:
```
$response = $mercantil->payment("4141-4141-4141-4141", "12/2024", "369", "tdc", "V12345678", "192.168.1.1", "Chrome", "65987412", 126.35);
```
En caso de error devuelve un array asociativo con dos keys: ResponseError (errores provenientes del banco) y DataSent (trama enviada para que pueda evaluar donde está el error).

En caso de éxito devuelve la respuesta tal como llega dle banco sin embargo si la transacción es aprovada, puede utilizar el método **$mercantil->IsApproved()** que devolverá true si se aprobó o false si se rechazó la transacción. También puede usar el método **$mercantil->getTransactionReferenceId()** para obtener la referencia o ID de la transacción para control bancario cuando se requiera.