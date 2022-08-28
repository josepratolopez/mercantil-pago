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
## métodos

payment(string $numeroTarjeta, string $fechaVencimientoTarjeta, string $cvvtarjeta, string $tipoTarjeta, string $cedulaCliente, string $direccionIpCliente, string $userAgentNavegador, string $idVenta, double $montoVenta, string $tipoCuenta = null): se utiliza para iniciar un proceso de pago.

## Datos POST del formulario de pago
(Boton de pago y formulario se obtiene mediante el llamado del método **_buttonHtml(string $uriLogo, string $uriActionPost, double $monto)**)

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