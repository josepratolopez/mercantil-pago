<?php
namespace Mercantil;

class AesCipher {

	private const OPENSSL_CIPHER_NAME = "aes-128-ecb";
	private const CIPHER_KEY_LEN = 16; //128 bits
	/**
	 * Encripta datos en AES ECB de 128 bit key
	 *
	 * @param type $keybank - Clave enviada
	 * @return keybankhash Hash en sha 256 de la clave enviada por el banco
	 */
	static function createKeyhash($keybank) {
		$keybankhash = hash("sha256", $keybank, true);
		# return substr($keybankhash, 0, 16);
		return $keybankhash;
	}
	/**
	 * Selecciona los primeros 16 byte del hash de la clave
	 *
	 * @param type $key - Hash en sha 256 de la clave enviada por el banco
	 * @return key 16 bytes de del hash de la clave enviada por el Banco
	 */
	private static function fixKey($key) {

		if (strlen($key) < AesCipher::CIPHER_KEY_LEN) {
			//0 pad to len 16
			return str_pad("$key", AesCipher::CIPHER_KEY_LEN, "0");
		}

		if (strlen($key) > AesCipher::CIPHER_KEY_LEN) {
			//truncate to 16 bytes
			return substr($key, 0, AesCipher::CIPHER_KEY_LEN);
		}

		return $key;
	}
	/**
	 * Encripta datos en AES ECB de 128 bit key
	 *
	 * @param type $key - Clave enviada por el banco debe ser de 16 bytes en sha-256
	 * @param type $data - Datos a ser cifrados
	 * @return encrypted Datos cifrados
	 */
	static function encrypt($key, $data) {

		$encodedEncryptedData = base64_encode(openssl_encrypt($data, AesCipher::OPENSSL_CIPHER_NAME, AesCipher::fixKey($key), OPENSSL_PKCS1_PADDING));
		return $encodedEncryptedData;

	}
	/**
	 * Desencripta datos en AES ECB de 128 bit key
	 *
	 * @param type $key - Clave enviada por el banco debe ser de 16 bytes en sha-256
	 * @param type $data - Datos a ser cifrados
	 * @return decrypted Datos Desencriptados
	 */
	static function decrypt($key, $data) {
		$decryptedData = openssl_decrypt(base64_decode($data), AesCipher::OPENSSL_CIPHER_NAME, AesCipher::fixKey($key), OPENSSL_PKCS1_PADDING);
		return $decryptedData;
	}
}
/**
 * Clase para implementacion de popup de pago con tarjetas nacionales
 * o internacionales usando la pasarela de pagos de Banco Mercantil para Venezuela
 * @author Jose Prato <ing.joseprato@gmail.com>
 */
class Pago extends AesCipher {

	function __construct($clientId, $merchantId, $cipherKey, $isProd = false) {
		$this->_clientId = $clientId;
		$this->_merchantId = $merchantId;
		$this->_cipherKey = $cipherKey;
		$this->_isProd = $isProd;
		$this->_isApproved = false;
		$this->_transactionReference = null;
	}
	private function getAuthEndpoint() {
		return $this->_isProd ? "https://apimbu.mercantilbanco.com/mercantil-banco/prod/v1/payment/getauth" : "https://apimbu.mercantilbanco.com/mercantil-banco/sandbox/v1/payment/getauth";
	}
	private function getPaymentEndpoint() {
		return $this->_isProd ? "https://apimbu.mercantilbanco.com/mercantil-banco/prod/v1/payment/pay" : "https://apimbu.mercantilbanco.com/mercantil-banco/sandbox/v1/payment/pay";
	}
	private function getPaymentSearchEndpoint() {
		return $this->_isProd ? "https://apimbu.mercantilbanco.com/mercantil-banco/prod/v1/payment/search" : "https://apimbu.mercantilbanco.com/mercantil-banco/sandbox/v1/payment/search";
	}
	private function setIsApproved($approved) {
		$this->_isApproved = $approved;
	}
	private function setTransactionReferenceId($id) {
		$this->_transactionReference = $id;
	}
	public function getTransactionReferenceId() {
		return $this->_transactionReference;
	}
	public function IsApproved() {
		return $this->_isApproved;
	}
	private function getAuth($cardNum, $custId, $ipAddr, $userAgent, $cardType) {
		$data = array(
			'merchant_identify' => array(
				'integratorId' => 1,
				'merchantId' => $this->_merchantId,
				'terminalId' => 1,
			),
			'client_identify' => array(
				'ipaddress' => $ipAddr,
				'browser_agent' => $userAgent,
			),
			'transaction_authInfo' => array(
				'trx_type' => 'solaut',
				'payment_method' => $cardType,
				'card_number' => $cardNum,
				'customer_id' => $custId,
			),
		);

		$curl = curl_init($this->getAuthEndpoint());
		curl_setopt($curl, CURLOPT_POST, true);
		curl_setopt($curl, CURLOPT_HTTPHEADER, array(
			"Content-type: application/json",
			"X-IBM-Client-Id: " . $this->_clientId,
		));
		curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode($data));
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
		$response = curl_exec($curl);
		curl_close($curl);
		return $response;

	}

	public function payment($cardNum, $expiryDate, $cvv, $cardType, $custId, $ipAddr, $userAgent, $invoiceNum, $amount, $accountType = null) {
		$cardNum = str_replace("-", "", $cardNum);
		if ($cardType == "tdd" and $accountType == null) {
			return json_encode(array("error_code" => "Si el tipo de tarjeta es debito Mercantil debe indicar el tipo de cuenta"));
		}

		$expiryDate = explode("/", $expiryDate);
		$expiryDate = $expiryDate[1] . "/" . $expiryDate[0];

		switch ($cardType) {
		case 'tdc':
			$data = array(
				'merchant_identify' => array(
					'integratorId' => 1,
					'merchantId' => $this->_merchantId,
					'terminalId' => 1,
				),
				'client_identify' => array(
					'ipaddress' => $ipAddr,
					'browser_agent' => $userAgent,
				),
				'transaction' => array(
					'trx_type' => 'compra',
					'payment_method' => $cardType,
					'card_number' => $cardNum,
					'customer_id' => $custId,
					'invoice_number' => $invoiceNum,
					'expiration_date' => $expiryDate,
					'cvv' => parent::encrypt(parent::createKeyhash($this->_cipherKey), $cvv),
					'currency' => 'ves',
					'amount' => $amount,
				),
			);
			$curl = curl_init($this->getPaymentEndpoint());
			curl_setopt($curl, CURLOPT_POST, true);
			curl_setopt($curl, CURLOPT_HTTPHEADER, array(
				"Content-type: application/json",
				"X-IBM-Client-Id: " . $this->_clientId,
			));
			curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode($data));
			curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
			$response = curl_exec($curl);
			$response = json_decode($response, true);
			curl_close($curl);
			if (isset($response['error_list'])) {
				$this->setIsApproved(false);
				$this->setTransactionReferenceId(null);
				return array("ResponseError" => $response['error_list'], "DataSent" => json_encode($data));
			}
			if ($response['transaction_response']['trx_status'] == 'approved') {
				$this->setIsApproved(true);
				$this->setTransactionReferenceId($response['transaction_response']['payment_reference']);
			} else {
				$this->setIsApproved(false);
				$this->setTransactionReferenceId(null);
			}
			return json_encode($response);

			break;

		case 'tdd':
			$twoAuthCode = json_decode($this->getAuth($cardNum, $custId, $ipAddr, $userAgent, $cardType), true);
			if (isset($twoAuthCode['authentication_info'])) {
				$data = array(
					'merchant_identify' => array(
						'integratorId' => 1,
						'merchantId' => $this->_merchantId,
						'terminalId' => 1,
					),
					'client_identify' => array(
						'ipaddress' => $ipAddr,
						'browser_agent' => $userAgent,
					),
					'transaction' => array(
						'trx_type' => 'compra',
						'payment_method' => $cardType,
						'card_number' => $cardNum,
						'customer_id' => $custId,
						'invoice_number' => $invoiceNum,
						'account_type' => $accountType,
						'twofactor_auth' => $twoAuthCode['authentication_info']['twofactor_type'],
						'expiration_date' => $expiryDate,
						'cvv' => parent::encrypt(parent::createKeyhash($this->_cipherKey), $cvv),
						'currency' => 'ves',
						'amount' => $amount,
					),
				);
				$curl = curl_init($this->getPaymentEndpoint());
				curl_setopt($curl, CURLOPT_POST, true);
				curl_setopt($curl, CURLOPT_HTTPHEADER, array(
					"Content-type: application/json",
					"X-IBM-Client-Id: " . $this->_clientId,
				));
				curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode($data));
				curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
				$response = curl_exec($curl);
				$response = json_decode($response, true);
				curl_close($curl);
				if (isset($response['error_list'])) {
					$this->setIsApproved(false);
					$this->setTransactionReferenceId(null);
					return array("ResponseError" => $response['error_list'], "DataSent" => json_encode($data));
				}
				if ($response['transaction_response']['trx_status'] == 'approved') {
					$this->setIsApproved(true);
					$this->setTransactionReferenceId($response['transaction_response']['payment_reference']);
				} else {
					$this->setIsApproved(false);
					$this->setTransactionReferenceId(null);
				}
				return json_encode($response);
			} else {
				$this->setIsApproved(false);
				$this->setTransactionReferenceId(null);
				return json_encode($twoAuthCode);
			}
			break;
		}

	}

	public function _buttonHtml($logoUri, $uriController, $amount) {
		$html = '
			<style>
				.row-wrapper{
					width: 100%;
				}
				.paymentMercantilFormWrapper a,.paymentMercantilFormWrapper span, .paymentMercantilFormWrapper p{
					font-family: arial
				}
				.paymentMercantilFormWrapper input,.paymentMercantilFormWrapper select{
					width: 100%;
					margin-top: 10px;
					padding-top: 6px;
					padding-bottom: 6px;
					border-radius: 3px;
					border-width: 1px;
				}
				.mercantil-paymentButton{
					background-color: #69bdff;
					color: white;
					font-weight: bold;
					text-decoration: none;
					padding: 5px 10px;
					border-radius: 5px;
					display: flex;
					vertical-align: center;
					justify-content: center;
					width: 100px;
					font-family: arial;
					border-color: #348dd1;
					box-shadow: 5px 5px 9px -5px rgba(0,0,0,0.75);
					-webkit-box-shadow: 5px 5px 9px -5px rgba(0,0,0,0.75);
					-moz-box-shadow: 5px 5px 9px -5px rgba(0,0,0,0.75);

				}
				.mercantil-paymentButton img{
					width: 20px;
					height: auto;

				}
				.paymentMercantilFormWrapper input:focus {
				  outline: none;
				}
				.align-flex-bottom{
					display: flex;
					align-items: bottom;
					justify-content: center;
				}
				.align-flex{
					display: flex;
					align-items: center;
					justify-content: center;
				}
			</style>
			<a href="#" class="mercantil-paymentButton">PAGAR&nbsp;&nbsp;<img src="data:image/png;base64,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"></a>
			<div class="paymentMercantilFormWrapper" style="visibility: hidden; display: flex; top: 0; left: 0; width: 100vw; height: 100vh; position: fixed; z-index: 1000000; align-items: center; justify-content: center; background-color: rgba(0,0,0,0.5); box-shadow: 5px 5px 9px -5px rgba(0,0,0,0.75); -webkit-box-shadow: 5px 5px 9px -5px rgba(0,0,0,0.75); -moz-box-shadow: 5px 5px 9px -5px rgba(0,0,0,0.75);">
				<form id="paymentMercantilForm" method="POST" action="' . $uriController . '">
					<div style="border-radius: 8px; background-color: #f9f9f9; width: 285px; padding: 10px">
						<div class="row-wrapper">
							<div style="width: 100%; display: inline-block; padding-top:10px; text-align: center">
								<img style="width: 200px; height: auto" src="' . $logoUri . '">
							</div>
						</div>
						<div class="row-wrapper">
							<div style="width: 100%; display: inline-block; position: relative">
								<input name="card-num" placeholder="Número de tarjeta" style="padding-left: 40px; background-repeat: no-repeat; background-position: 5px 2px; background-image: url(\'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAABHNCSVQICAgIfAhkiAAAAAlwSFlzAAAApgAAAKYB3X3/OAAAABl0RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAADjSURBVEiJ7ZU5bsJQFEXPNU5kIYZI6dkHG0jNFrIRFkFJ48p9ajpWQbpI9CihCLII6NIYCTEEgv53lVu/d07zBtkmZpKo9DoEKYCkHtAMzF7ZngsYAy/AV2DBEzAR8A082y5D0iVlwCIBGqHhABWzkQKJpEFoQZVEgIFlJEF3L4iWFNgAeST+q4DSdhaDLqmsZ5MPjA/AEGhd6RvZ/vizwPaPpBnQ+aXHwOct8BOBpEegD7SP6nLb01uhFwW215Lezghm98ABapmibXWYQsMzYJsCBfAuKca5LmQ77sP5f/rXsgOb404sjpF0jQAAAABJRU5ErkJggg==\')">
								<img class="brand-card" src="" style="width: 29px; height: auto;position: absolute; right: 7px;top: 15px; display: none">
							</div>
						</div>
						<div class="row-wrapper">
							<div style="width: 100%; display: inline-block; position: relative">
								<select name="card-type" style="padding-left: 40px; background-repeat: no-repeat; background-position: 5px 2px; background-image: url(\'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAABHNCSVQICAgIfAhkiAAAAAlwSFlzAAAApgAAAKYB3X3/OAAAABl0RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAADjSURBVEiJ7ZU5bsJQFEXPNU5kIYZI6dkHG0jNFrIRFkFJ48p9ajpWQbpI9CihCLII6NIYCTEEgv53lVu/d07zBtkmZpKo9DoEKYCkHtAMzF7ZngsYAy/AV2DBEzAR8A082y5D0iVlwCIBGqHhABWzkQKJpEFoQZVEgIFlJEF3L4iWFNgAeST+q4DSdhaDLqmsZ5MPjA/AEGhd6RvZ/vizwPaPpBnQ+aXHwOct8BOBpEegD7SP6nLb01uhFwW215Lezghm98ABapmibXWYQsMzYJsCBfAuKca5LmQ77sP5f/rXsgOb404sjpF0jQAAAABJRU5ErkJggg==\')">
									<option value="">Seleccione tipo de tarjeta...</option>
									<option value="tdc">CREDITO / DEBITO NACIONAL O INTERNACIONAL</option>
									<option value="tdd">DEBITO BANCO MERCANTIL</option>
								</select>
							</div>
						</div>
						<div class="row-wrapper" style="display: none">
							<div style="width: 100%; display: inline-block; position: relative">
								<select name="account-type" style="padding-left: 40px; background-repeat: no-repeat; background-position: 5px 2px; background-image: url(\'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAABHNCSVQICAgIfAhkiAAAAAlwSFlzAAAApgAAAKYB3X3/OAAAABl0RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAADjSURBVEiJ7ZU5bsJQFEXPNU5kIYZI6dkHG0jNFrIRFkFJ48p9ajpWQbpI9CihCLII6NIYCTEEgv53lVu/d07zBtkmZpKo9DoEKYCkHtAMzF7ZngsYAy/AV2DBEzAR8A082y5D0iVlwCIBGqHhABWzkQKJpEFoQZVEgIFlJEF3L4iWFNgAeST+q4DSdhaDLqmsZ5MPjA/AEGhd6RvZ/vizwPaPpBnQ+aXHwOct8BOBpEegD7SP6nLb01uhFwW215Lezghm98ABapmibXWYQsMzYJsCBfAuKca5LmQ77sP5f/rXsgOb404sjpF0jQAAAABJRU5ErkJggg==\')">
									<option value="">Seleccione tipo de cuenta...</option>
									<option value="CA">Cuenta de Ahorro</option>
									<option value="CC">Cuenta Corriente</option>
								</select>
							</div>
						</div>
						<div class="row-wrapper">
							<div style="width: 49%; display: inline-block; vertical-align:bottom">
								<input name="due-date" maxlength="7" placeholder="Vencimiento" style="padding-left: 40px; background-repeat: no-repeat; background-position: 5px 3px; background-size: 20px; background-image: url(\'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAABHNCSVQICAgIfAhkiAAAAAlwSFlzAAAApgAAAKYB3X3/OAAAABl0RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAAHNSURBVEiJxdXNS5RxEMDxz8imsYkoqAiiiaBEh5DYQ9A16Cr+FXVqO9XJc/9B0K1jYCCdvHSKTnUQD0EHac2DhwhfoFjs8HTY2Xg03XZjy4Efz3yfeXtmZvd5FEWhfTCKApvl+90cbGbsaPl+RUpEVDGbOBgRc3qTwbzORsRxURTf24YJPMVRPkE/zlHmnKjgAe7hM7ZwG9/wvscOariCt5jJnF9hD4e4rE87yFyH2KtgCjtFUTQjYgDPs5te5VUWOc5c+7gaWXUXN/4iaSfZwky7wD+T9s/0Bz70Ofd1XKLVQaPXpXax9AaKgXLJiJiKiFsRMZW8mFxNrkVELfVq2hbPii3Lrw5QT64nrycvJR/gIPWltK2fE9tAUXFSPuJFXuENmthPflny3U/fd+fE/t7B/9hBLSIel+a8kjyZXI+IeuqTaVs5K/bCdvAa97VeWLTeiBta/3R4WPLdTd9P58RezA6WI2IjIpaTV5Pnk9ciYi31+bStnn7ispwe0Rzu5ljgZvJI8p2S70jamp0KnBgRxnANY8nTyUPJC1hIfSht051GBNtaX7DxPs5/PHNuV/AMT7ATEV/+1G6XMoFq5jaMR9lJvz7625lz+Cf6oyuFJp26UAAAAABJRU5ErkJggg==\')">
							</div>
							<div style="width: 49%; display: inline-block">
								<input name="cvv" maxlength="4" placeholder="CVV" style="padding-left: 40px; background-repeat: no-repeat; background-position: 5px 2px; background-image: url(\'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAABHNCSVQICAgIfAhkiAAAAAlwSFlzAAAApgAAAKYB3X3/OAAAABl0RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAADjSURBVEiJ7ZU5bsJQFEXPNU5kIYZI6dkHG0jNFrIRFkFJ48p9ajpWQbpI9CihCLII6NIYCTEEgv53lVu/d07zBtkmZpKo9DoEKYCkHtAMzF7ZngsYAy/AV2DBEzAR8A082y5D0iVlwCIBGqHhABWzkQKJpEFoQZVEgIFlJEF3L4iWFNgAeST+q4DSdhaDLqmsZ5MPjA/AEGhd6RvZ/vizwPaPpBnQ+aXHwOct8BOBpEegD7SP6nLb01uhFwW215Lezghm98ABapmibXWYQsMzYJsCBfAuKca5LmQ77sP5f/rXsgOb404sjpF0jQAAAABJRU5ErkJggg==\')">
							</div>
						</div>
						<div class="row-wrapper">
							<div style="width: 49%; display: inline-block; vertical-align:bottom">
								<input name="user-firstname" placeholder="Nombre" style="padding-left: 40px; background-repeat: no-repeat; background-position: 5px 3px; background-size: 20px; background-image: url(\'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAABHNCSVQICAgIfAhkiAAAAAlwSFlzAAAApgAAAKYB3X3/OAAAABl0RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAAH/SURBVEiJrdbNi01xGMDxz++aiEK6K4lm2BqMlzASmoWS/AvGziyUFGU1SzZWLCYslCRZSLKRlRRmGm9NVl6miSTvI0w087P4/cZcc+89d7rmqVPnPL/nPN/nPG8dMUZFF1pwBLfxES9xFbsavRtj1Mh5GwbwC1dwHCdwDxM4g1JTgBx5P16go8Z5D8ZxrFnAYfzGpgKbkxhDazOAG7jZIIUL81fsr2dTUl/a8bTgXIzxG55jXT2bIsAnlIsAWcr40AzgCbaHEFrqGYQQNmTAw7peCvK7USpyb53zeXiUA5nb7Bz0IuIclmZdCVuy4zGsbXrQssNufM6gd/ie7wewutH7ITuZntsy1udob2EJOtGBrxjEA2mad0uTPhhj/NKwBjiKHznKmB111rDbmWswaTeKQ4UpwsFsfAqt2IahrBvCRVzCs6x7nJthJU5nXXdNABblKPqmQQP24Tzu4g7OYg8pxRW2F6T5WVAL0JPbclmjwhU0RKu0Og7UWhVd6I8xvqkq1Awlxjic09Y1qasEtON+s84rpD/7qgIsx6tZALzOvqYAIYQ5mI+fswAYldb4FCDGOI732DoLgM14+/epogOuSVO6+D+6qCytkstVqyKEsErqgIDrUs9X75HaUsIO7JVafU2MceSfL8igNunvYcTUCpjJNYFhacpXVPr8A5ma6p0xqaUXAAAAAElFTkSuQmCC\')">
							</div>
							<div style="width: 49%; display: inline-block">
								<input name="user-lastname" placeholder="Apellido" style="padding-left: 40px; background-repeat: no-repeat; background-position: 5px 3px; background-size: 20px; background-image: url(\'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAABHNCSVQICAgIfAhkiAAAAAlwSFlzAAAApgAAAKYB3X3/OAAAABl0RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAAH/SURBVEiJrdbNi01xGMDxz++aiEK6K4lm2BqMlzASmoWS/AvGziyUFGU1SzZWLCYslCRZSLKRlRRmGm9NVl6miSTvI0w087P4/cZcc+89d7rmqVPnPL/nPN/nPG8dMUZFF1pwBLfxES9xFbsavRtj1Mh5GwbwC1dwHCdwDxM4g1JTgBx5P16go8Z5D8ZxrFnAYfzGpgKbkxhDazOAG7jZIIUL81fsr2dTUl/a8bTgXIzxG55jXT2bIsAnlIsAWcr40AzgCbaHEFrqGYQQNmTAw7peCvK7USpyb53zeXiUA5nb7Bz0IuIclmZdCVuy4zGsbXrQssNufM6gd/ie7wewutH7ITuZntsy1udob2EJOtGBrxjEA2mad0uTPhhj/NKwBjiKHznKmB111rDbmWswaTeKQ4UpwsFsfAqt2IahrBvCRVzCs6x7nJthJU5nXXdNABblKPqmQQP24Tzu4g7OYg8pxRW2F6T5WVAL0JPbclmjwhU0RKu0Og7UWhVd6I8xvqkq1Awlxjic09Y1qasEtON+s84rpD/7qgIsx6tZALzOvqYAIYQ5mI+fswAYldb4FCDGOI732DoLgM14+/epogOuSVO6+D+6qCytkstVqyKEsErqgIDrUs9X75HaUsIO7JVafU2MceSfL8igNunvYcTUCpjJNYFhacpXVPr8A5ma6p0xqaUXAAAAAElFTkSuQmCC\')">
							</div>
						</div>
						<div class="row-wrapper">
							<div style="width: 100%; display: inline-block">
								<input name="user-docid" placeholder="Documento de identidad" style="padding-left: 40px; background-repeat: no-repeat; background-position: 5px 4px; background-size: 20px; background-image: url(\'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAABHNCSVQICAgIfAhkiAAAAAlwSFlzAAAApgAAAKYB3X3/OAAAABl0RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAAH/SURBVEiJrdbNi01xGMDxz++aiEK6K4lm2BqMlzASmoWS/AvGziyUFGU1SzZWLCYslCRZSLKRlRRmGm9NVl6miSTvI0w087P4/cZcc+89d7rmqVPnPL/nPN/nPG8dMUZFF1pwBLfxES9xFbsavRtj1Mh5GwbwC1dwHCdwDxM4g1JTgBx5P16go8Z5D8ZxrFnAYfzGpgKbkxhDazOAG7jZIIUL81fsr2dTUl/a8bTgXIzxG55jXT2bIsAnlIsAWcr40AzgCbaHEFrqGYQQNmTAw7peCvK7USpyb53zeXiUA5nb7Bz0IuIclmZdCVuy4zGsbXrQssNufM6gd/ie7wewutH7ITuZntsy1udob2EJOtGBrxjEA2mad0uTPhhj/NKwBjiKHznKmB111rDbmWswaTeKQ4UpwsFsfAqt2IahrBvCRVzCs6x7nJthJU5nXXdNABblKPqmQQP24Tzu4g7OYg8pxRW2F6T5WVAL0JPbclmjwhU0RKu0Og7UWhVd6I8xvqkq1Awlxjic09Y1qasEtON+s84rpD/7qgIsx6tZALzOvqYAIYQ5mI+fswAYldb4FCDGOI732DoLgM14+/epogOuSVO6+D+6qCytkstVqyKEsErqgIDrUs9X75HaUsIO7JVafU2MceSfL8igNunvYcTUCpjJNYFhacpXVPr8A5ma6p0xqaUXAAAAAElFTkSuQmCC\')">
							</div>
						</div>
						<div class="row-wrapper">
							<div style="width: 100%; display: inline-block">
								<input name="user-email" placeholder="Correo electrónico" style="padding-left: 40px; background-repeat: no-repeat; background-position: 5px 4px; background-size: 20px; background-image: url(\'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAABHNCSVQICAgIfAhkiAAAAAlwSFlzAAAApgAAAKYB3X3/OAAAABl0RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAAFmSURBVEiJ1dU9L0RREMbx39m1JOIlkdBoaJQarS+g3Gj0Ct9Ap9KpFSqdhEolOhqJ3KBTqSQKjWiUiqMZcbF37dpdiUmmuPPyf3LmzslJOWeDtNpA6X8hAMsokPvsRbAVeMJqzlk/HKvBLITaIh6w0Qf4RrAWgy1HYh532OoBvhWM+fj+EIjADG6wi1oX4Fr03GCmFP8sEMFxnOEIwx3Ah6P2DONfcvnbmuacX7CCOk5SSmNV6xe5k6hdid5vltscew9XmG6Rn47cXtU4W46oRdF2/Li5UmwuYts/9OahquPHCBIm0cBFSmktUod4xWRKKb2vYZVVjaiBA5xjAk1chzcjdh41ja5GhFGc4hgjbUYwEjWnGO1IAFO4xD7qHaxpPWovMdVWALO4xc4vbvFO9M62FMAC7rHZLbwE3AzGwicBLOER67+Fl0TWg7X0LlDgGc1e4SWRZjALBvzgpB/uSM/2/x/9N7+AAjsqN2LMAAAAAElFTkSuQmCC\')">
							</div>
						</div>
						<div class="row-wrapper">
							<div style="width: 100%; display: inline-block; padding-top:10px">
								<button href="#" type="submit" style="background-color: gray;color: white; width: 100%; border-width: 0px; border-radius: 5px; padding: 7px 0px;" id="payNowButton" disabled>PAGAR AHORA Bs ' . $amount . '</button>
							</div>
						</div>
						<div class="row-wrapper">
							<div style="width: 100%; display: inline-block; padding-top:10px; text-align: right">
								<img style="width: 100px; height: auto" src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAJYAAABCCAYAAAC1ri/bAAAACXBIWXMAAAsTAAALEwEAmpwYAAAFFmlUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4gPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iQWRvYmUgWE1QIENvcmUgNS42LWMxNDggNzkuMTY0MDM2LCAyMDE5LzA4LzEzLTAxOjA2OjU3ICAgICAgICAiPiA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPiA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtbG5zOmRjPSJodHRwOi8vcHVybC5vcmcvZGMvZWxlbWVudHMvMS4xLyIgeG1sbnM6cGhvdG9zaG9wPSJodHRwOi8vbnMuYWRvYmUuY29tL3Bob3Rvc2hvcC8xLjAvIiB4bWxuczp4bXBNTT0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL21tLyIgeG1sbnM6c3RFdnQ9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9zVHlwZS9SZXNvdXJjZUV2ZW50IyIgeG1wOkNyZWF0b3JUb29sPSJBZG9iZSBQaG90b3Nob3AgMjEuMCAoV2luZG93cykiIHhtcDpDcmVhdGVEYXRlPSIyMDIyLTA4LTI2VDE2OjAyOjQzLTA1OjAwIiB4bXA6TW9kaWZ5RGF0ZT0iMjAyMi0wOC0yNlQxNjowNDo0MS0wNTowMCIgeG1wOk1ldGFkYXRhRGF0ZT0iMjAyMi0wOC0yNlQxNjowNDo0MS0wNTowMCIgZGM6Zm9ybWF0PSJpbWFnZS9wbmciIHBob3Rvc2hvcDpDb2xvck1vZGU9IjMiIHBob3Rvc2hvcDpJQ0NQcm9maWxlPSJzUkdCIElFQzYxOTY2LTIuMSIgeG1wTU06SW5zdGFuY2VJRD0ieG1wLmlpZDpiYmEyMzUyOS1kNzUxLWQ3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">
							</div>
						</div>
					</div>
					<input type="hidden" name="amount" value="' . $amount . '">
				</form>
			</div>
			<script>
		        function fadeIn(el, display) {
		            el.style.opacity = 0;
		            el.style.visibility = "visible";
		            (function fade() {
		                var val = parseFloat(el.style.opacity);
		                if (!((val += .1) > 1)) {
		                    el.style.opacity = val;
		                    requestAnimationFrame(fade);
		                }
		            })();
		        };
		        function fadeOut(el) {
		            el.style.opacity = 1;
		            (function fade() {
		                if ((el.style.opacity -= .1) < 0) {
		                    el.style.visibility = "hidden";
		                } else {
		                    requestAnimationFrame(fade);
		                }
		            })();
		        };
				var card = "";
				function checkEnablePayButton(){
					aux = true;
					const inputs = document.getElementsByTagName("input");
					const selects = document.getElementsByTagName("select");
					for (var i = 0, len = inputs.length; i < len; i++) {
					    if(inputs[i].value==""){
					    	aux = false;
					    }
					}
					for (var i = 0, len = selects.length; i < len; i++) {
						if(selects[i].parentNode.parentNode.style.display != "none"){
							if(selects[i].value==""){
						    	aux = false;
						    }
						}
					}
					if(aux){
						document.querySelector("#payNowButton").disabled = false;
						document.querySelector("#payNowButton").style.backgroundColor = "green";
					}
					else{
						document.querySelector("#payNowButton").disabled = true;
						document.querySelector("#payNowButton").style.backgroundColor = "gray";
					}
				}
				const paymentButton = document.querySelector(".mercantil-paymentButton");
				const wrapper = document.querySelector(".paymentMercantilFormWrapper");
				const inputCard = document.querySelector("input[name=\'card-num\']");
				const inputDuedate = document.querySelector("input[name=\'due-date\']");
				const inputEmail = document.querySelector("input[name=\'user-email\']");
				const inputCvv = document.querySelector("input[name=\'cvv\']");
				const inputFirstname = document.querySelector("input[name=\'user-firstname\']");
				const inputLastname = document.querySelector("input[name=\'user-lastname\']");
				const inputDocid = document.querySelector("input[name=\'user-docid\']");
				const selectCardType = document.querySelector("select[name=\'card-type\']");
				const selectAccountType = document.querySelector("select[name=\'account-type\']");
				wrapper.addEventListener("click", (e) => {
					//fadeOut(document.querySelector(".paymentMercantilFormWrapper"));
				});
				paymentButton.addEventListener("click", (e) => {
					fadeIn(document.querySelector(".paymentMercantilFormWrapper"));
				});
				selectAccountType.addEventListener("change", (e) => {
					if(e.target.value.length!=""){
						e.target.style.borderColor = "#575757";
						checkEnablePayButton();
					}
					else{
						e.target.style.borderColor = "red";
						document.querySelector("#payNowButton").disabled = true;
						document.querySelector("#payNowButton").style.backgroundColor = "gray";
					}
				});
				selectCardType.addEventListener("change", (e) => {
					if(e.target.value == "tdd"){
						document.querySelector("select[name=\'account-type\']").parentNode.parentNode.style.display = "block";
					}
					else{
						document.querySelector("select[name=\'account-type\']").parentNode.parentNode.style.display = "none";

					}
					if(e.target.value.length!=""){
						e.target.style.borderColor = "#575757";
						checkEnablePayButton();
					}
					else{
						e.target.style.borderColor = "red";
						document.querySelector("#payNowButton").disabled = true;
						document.querySelector("#payNowButton").style.backgroundColor = "gray";
					}
				});
				inputCvv.addEventListener("keyup", (e) => {
					if(e.target.value.length>0){
						e.target.style.borderColor = "#575757";
						checkEnablePayButton();
					}
					else{
						e.target.style.borderColor = "red";
						document.querySelector("#payNowButton").disabled = true;
						document.querySelector("#payNowButton").style.backgroundColor = "gray";
					}
				});
				inputFirstname.addEventListener("keyup", (e) => {
					const re = /^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/g;
					if(e.target.value.length>0){
						e.target.style.borderColor = "#575757";
						checkEnablePayButton();
					}
					else{
						e.target.style.borderColor = "red";
						document.querySelector("#payNowButton").disabled = true;
						document.querySelector("#payNowButton").style.backgroundColor = "gray";
					}
				});
				inputLastname.addEventListener("keyup", (e) => {
					const re = /^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/g;
					if(e.target.value.length>0){
						e.target.style.borderColor = "#575757";
						checkEnablePayButton();
					}
					else{
						e.target.style.borderColor = "red";
						document.querySelector("#payNowButton").disabled = true;
						document.querySelector("#payNowButton").style.backgroundColor = "gray";
					}
				});
				inputDocid.addEventListener("keyup", (e) => {
					const re = /^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/g;
					if(e.target.value.length>0){
						e.target.style.borderColor = "#575757";
						checkEnablePayButton();
					}
					else{
						e.target.style.borderColor = "red";
						document.querySelector("#payNowButton").disabled = true;
						document.querySelector("#payNowButton").style.backgroundColor = "gray";
					}
				});
				inputEmail.addEventListener("keyup", (e) => {
					const re = /^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/g;
					if(re.test(String(e.target.value).toLowerCase()) || e.target.value==""){
						e.target.style.borderColor = "#575757";
						checkEnablePayButton();
					}
					else{
						e.target.style.borderColor = "red";
						document.querySelector("#payNowButton").disabled = true;
						document.querySelector("#payNowButton").style.backgroundColor = "gray";
					}
				});
				inputDuedate.addEventListener("keypress", (e) => {
					if(e.target.value.length == 2){
						e.target.value = e.target.value + "/";
					}
				});
				inputDuedate.addEventListener("keyup", (e) => {
					const re = /([0-9]{2})\/([0-9]{4})/g;
					if(re.test(String(e.target.value).toLowerCase()) || e.target.value==""){
						e.target.style.borderColor = "#575757";
						checkEnablePayButton();
					}
					else{
						e.target.style.borderColor = "red";
						document.querySelector("#payNowButton").disabled = true;
						document.querySelector("#payNowButton").style.backgroundColor = "gray";
					}
				});
				inputCard.addEventListener("keypress", (e) => {
					if(card == "visa" || card == "master"){
						if(e.target.value.length == 4 || e.target.value.length == 9 || e.target.value.length == 14){
							e.target.value = e.target.value + "-";
						}
					}
					else{
						if(e.target.value.length == 4 || e.target.value.length == 11){
							e.target.value = e.target.value + "-";
						}
					}

				});
				inputCard.addEventListener("keyup", (e) => {
					if(card == "visa" || card == "master"){
						const re = /([0-9]{4})-([0-9]{4})-([0-9]{4})-([0-9]{4})/g;
						if(re.test(String(e.target.value).toLowerCase()) || e.target.value==""){
							e.target.style.borderColor = "#575757";
							checkEnablePayButton();
						}
						else{
							e.target.style.borderColor = "red";
							document.querySelector("#payNowButton").disabled = true;
							document.querySelector("#payNowButton").style.backgroundColor = "gray";
						}
					}
					else if(card == "diners"){
						const re = /([0-9]{4})-([0-9]{6})-([0-9]{4})/g;
						if(re.test(String(e.target.value).toLowerCase()) || e.target.value==""){
							e.target.style.borderColor = "#575757";
							checkEnablePayButton();
						}
						else{
							e.target.style.borderColor = "red";
							document.querySelector("#payNowButton").disabled = true;
							document.querySelector("#payNowButton").style.backgroundColor = "gray";
						}
					}
					else if(card == "amex"){
						const re = /([0-9]{4})-([0-9]{6})-([0-9]{5})/g;
						if(re.test(String(e.target.value).toLowerCase()) || e.target.value==""){
							e.target.style.borderColor = "#575757";
							checkEnablePayButton();
						}
						else{
							e.target.style.borderColor = "red";
							document.querySelector("#payNowButton").disabled = true;
							document.querySelector("#payNowButton").style.backgroundColor = "gray";
						}
					}
					else{
						e.target.style.borderColor = "red";
						document.querySelector("#payNowButton").disabled = true;
						document.querySelector("#payNowButton").style.backgroundColor = "gray";
					}
				    if(e.target.value[0]+e.target.value[1]==36){
				    	inputCard.maxLength = 16;
				    	card = "diners";
				    	document.querySelector(".brand-card").style.display = "inherit";
				    	document.querySelector(".brand-card").src = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAGQAAABkCAIAAAD/gAIDAAABN2lDQ1BBZG9iZSBSR0IgKDE5OTgpAAAokZWPv0rDUBSHvxtFxaFWCOLgcCdRUGzVwYxJW4ogWKtDkq1JQ5ViEm6uf/oQjm4dXNx9AidHwUHxCXwDxamDQ4QMBYvf9J3fORzOAaNi152GUYbzWKt205Gu58vZF2aYAoBOmKV2q3UAECdxxBjf7wiA10277jTG+38yH6ZKAyNguxtlIYgK0L/SqQYxBMygn2oQD4CpTto1EE9AqZf7G1AKcv8ASsr1fBBfgNlzPR+MOcAMcl8BTB1da4Bakg7UWe9Uy6plWdLuJkEkjweZjs4zuR+HiUoT1dFRF8jvA2AxH2w3HblWtay99X/+PRHX82Vun0cIQCw9F1lBeKEuf1UYO5PrYsdwGQ7vYXpUZLs3cLcBC7dFtlqF8hY8Dn8AwMZP/fNTP8gAAAAJcEhZcwAACxMAAAsTAQCanBgAAAYGaVRYdFhNTDpjb20uYWRvYmUueG1wAAAAAAA8P3hwYWNrZXQgYmVnaW49Iu+7vyIgaWQ9Ilc1TTBNcENlaGlIenJlU3pOVGN6a2M5ZCI/PiA8eDp4bXBtZXRhIHhtbG5zOng9ImFkb2JlOm5zOm1ldGEvIiB4OnhtcHRrPSJBZG9iZSBYTVAgQ29yZSA1LjYtYzE0OCA3OS4xNjQwMzYsIDIwMTkvMDgvMTMtMDE6MDY6NTcgICAgICAgICI+IDxyZGY6UkRGIHhtbG5zOnJkZj0iaHR0cDovL3d3dy53My5vcmcvMTk5OS8wMi8yMi1yZGYtc3ludGF4LW5zIyI+IDxyZGY6RGVzY3JpcHRpb24gcmRmOmFib3V0PSIiIHhtbG5zOnhtcD0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wLyIgeG1sbnM6ZGM9Imh0dHA6Ly9wdXJsLm9yZy9kYy9lbGVtZW50cy8xLjEvIiB4bWxuczpwaG90b3Nob3A9Imh0dHA6Ly9ucy5hZG9iZS5jb20vcGhvdG9zaG9wLzEuMC8iIHhtbG5zOnhtcE1NPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvbW0vIiB4bWxuczpzdEV2dD0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL3NUeXBlL1Jlc291cmNlRXZlbnQjIiB4bXA6Q3JlYXRlRGF0ZT0iMjAxOC0wMS0wOVQxNzo0MjoxNC0wNTowMCIgeG1wOk1vZGlmeURhdGU9IjIwMjItMDgtMjZUMTU6MjA6NDYtMDU6MDAiIHhtcDpNZXRhZGF0YURhdGU9IjIwMjItMDgtMjZUMTU6MjA6NDYtMDU6MDAiIHhtcDpDcmVhdG9yVG9vbD0iQWRvYmUgUGhvdG9zaG9wIENDIDIwMTcgKFdpbmRvd3MpIiBkYzpmb3JtYXQ9ImltYWdlL3BuZyIgcGhvdG9zaG9wOkNvbG9yTW9kZT0iMyIgcGhvdG9zaG9wOklDQ1Byb2ZpbGU9IkFkb2JlIFJHQiAoMTk5OCkiIHhtcE1NOkluc3RhbmNlSUQ9InhtcC5paWQ6YmJhMGZmNzEtN2VhNC02MjQ0LWFjYTUtMjQ2MWJmYzNlYTA3IiB4bXBNTTpEb2N1bWVudElEPSJhZG9iZTpkb2NpZDpwaG90b3Nob3A6ODg5ODEzNzUtOWU1MS00MDQ2LWFjOWItNTU0N2E0OWYxNmNlIiB4bXBNTTpPcmlnaW5hbERvY3VtZW50SUQ9InhtcC5kaWQ6NTQxNTgwNDktNzRhOS0zODQxLWJjNDYtMWFiMzAzZmRmMDhlIj4gPHhtcE1NOkhpc3Rvcnk+IDxyZGY6U2VxPiA8cmRmOmxpIHN0RXZ0OmFjdGlvbj0ic2F2ZWQiIHN0RXZ0Omluc3RhbmNlSUQ9InhtcC5paWQ6NTQxNTgwNDktNzRhOS0zODQxLWJjNDYtMWFiMzAzZmRmMDhlIiBzdEV2dDp3aGVuPSIyMDE4LTAxLTA5VDE3OjQ4OjA1LTA1OjAwIiBzdEV2dDpzb2Z0d2FyZUFnZW50PSJBZG9iZSBQaG90b3Nob3AgQ0MgMjAxNyAoV2luZG93cykiIHN0RXZ0OmNoYW5nZWQ9Ii8iLz4gPHJkZjpsaSBzdEV2dDphY3Rpb249InNhdmVkIiBzdEV2dDppbnN0YW5jZUlEPSJ4bXAuaWlkOmJiYTBmZjcxLTdlYTQtNjI0NC1hY2E1LTI0NjFiZmMzZWEwNyIgc3RFdnQ6d2hlbj0iMjAyMi0wOC0yNlQxNToyMDo0Ni0wNTowMCIgc3RFdnQ6c29mdHdhcmVBZ2VudD0iQWRvYmUgUGhvdG9zaG9w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";
				    }
				    else if(e.target.value[0]+e.target.value[1]==37 || e.target.value[0]+e.target.value[1]==34){
				    	inputCard.maxLength = 17;
				    	card = "amex";
				    	document.querySelector(".brand-card").style.display = "inherit";
				    	document.querySelector(".brand-card").src = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAGQAAABkCAIAAAD/gAIDAAABN2lDQ1BBZG9iZSBSR0IgKDE5OTgpAAAokZWPv0rDUBSHvxtFxaFWCOLgcCdRUGzVwYxJW4ogWKtDkq1JQ5ViEm6uf/oQjm4dXNx9AidHwUHxCXwDxamDQ4QMBYvf9J3fORzOAaNi152GUYbzWKt205Gu58vZF2aYAoBOmKV2q3UAECdxxBjf7wiA10277jTG+38yH6ZKAyNguxtlIYgK0L/SqQYxBMygn2oQD4CpTto1EE9AqZf7G1AKcv8ASsr1fBBfgNlzPR+MOcAMcl8BTB1da4Bakg7UWe9Uy6plWdLuJkEkjweZjs4zuR+HiUoT1dFRF8jvA2AxH2w3HblWtay99X/+PRHX82Vun0cIQCw9F1lBeKEuf1UYO5PrYsdwGQ7vYXpUZLs3cLcBC7dFtlqF8hY8Dn8AwMZP/fNTP8gAAAAJcEhZcwAACxMAAAsTAQCanBgAAAYGaVRYdFhNTDpjb20uYWRvYmUueG1wAAAAAAA8P3hwYWNrZXQgYmVnaW49Iu+7vyIgaWQ9Ilc1TTBNcENlaGlIenJlU3pOVGN6a2M5ZCI/PiA8eDp4bXBtZXRhIHhtbG5zOng9ImFkb2JlOm5zOm1ldGEvIiB4OnhtcHRrPSJBZG9iZSBYTVAgQ29yZSA1LjYtYzE0OCA3OS4xNjQwMzYsIDIwMTkvMDgvMTMtMDE6MDY6NTcgICAgICAgICI+IDxyZGY6UkRGIHhtbG5zOnJkZj0iaHR0cDovL3d3dy53My5vcmcvMTk5OS8wMi8yMi1yZGYtc3ludGF4LW5zIyI+IDxyZGY6RGVzY3JpcHRpb24gcmRmOmFib3V0PSIiIHhtbG5zOnhtcD0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wLyIgeG1sbnM6ZGM9Imh0dHA6Ly9wdXJsLm9yZy9kYy9lbGVtZW50cy8xLjEvIiB4bWxuczpwaG90b3Nob3A9Imh0dHA6Ly9ucy5hZG9iZS5jb20vcGhvdG9zaG9wLzEuMC8iIHhtbG5zOnhtcE1NPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvbW0vIiB4bWxuczpzdEV2dD0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL3NUeXBlL1Jlc291cmNlRXZlbnQjIiB4bXA6Q3JlYXRlRGF0ZT0iMjAxOC0wMS0wOVQxNzo0MjoxNC0wNTowMCIgeG1wOk1vZGlmeURhdGU9IjIwMjItMDgtMjZUMTU6MTg6NTktMDU6MDAiIHhtcDpNZXRhZGF0YURhdGU9IjIwMjItMDgtMjZUMTU6MTg6NTktMDU6MDAiIHhtcDpDcmVhdG9yVG9vbD0iQWRvYmUgUGhvdG9zaG9wIENDIDIwMTcgKFdpbmRvd3MpIiBkYzpmb3JtYXQ9ImltYWdlL3BuZyIgcGhvdG9zaG9wOkNvbG9yTW9kZT0iMyIgcGhvdG9zaG9wOklDQ1Byb2ZpbGU9IkFkb2JlIFJHQiAoMTk5OCkiIHhtcE1NOkluc3RhbmNlSUQ9InhtcC5paWQ6MjE2Y2YwOGYtYWEzNi05ZTQxLTkxOTMtZmE0MTMzNzhlMjI3IiB4bXBNTTpEb2N1bWVudElEPSJhZG9iZTpkb2NpZDpwaG90b3Nob3A6OTJlZGUwYjItODEyMS1kMTQyLTk3M2MtYWM1MTJlMGEwN2RkIiB4bXBNTTpPcmlnaW5hbERvY3VtZW50SUQ9InhtcC5kaWQ6NTQxNTgwNDktNzRhOS0zODQxLWJjNDYtMWFiMzAzZmRmMDhlIj4gPHhtcE1NOkhpc3Rvcnk+IDxyZGY6U2VxPiA8cmRmOmxpIHN0RXZ0OmFjdGlvbj0ic2F2ZWQiIHN0RXZ0Omluc3RhbmNlSUQ9InhtcC5paWQ6NTQxNTgwNDktNzRhOS0zODQxLWJjNDYtMWFiMzAzZmRmMDhlIiBzdEV2dDp3aGVuPSIyMDE4LTAxLTA5VDE3OjQ4OjA1LTA1OjAwIiBzdEV2dDpzb2Z0d2FyZUFnZW50PSJBZG9iZSBQaG90b3Nob3AgQ0MgMjAxNyAoV2luZG93cykiIHN0RXZ0OmNoYW5nZWQ9Ii8iLz4gPHJkZjpsaSBzdEV2dDphY3Rpb249InNhdmVkIiBzdEV2dDppbnN0YW5jZUlEPSJ4bXAuaWlkOjIxNmNmMDhmLWFhMzYtOWU0MS05MTkzLWZhNDEzMzc4ZTIyNyIgc3RFdnQ6d2hlbj0iMjAyMi0wOC0yNlQxNToxODo1OS0wNTowMCIgc3RFdnQ6c29mdHdhcmVBZ2VudD0iQWRvYmUgUGhvdG9zaG9w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VPbsGudnTX7P78fnou/MRuv7/Sfm41/637MsCAiBopGKenIuOrSYVHzSgoixGHPZo6tWle491b1vqut52H0m2jTg7xgJAMzHLELadhM1EznV0rdcNHDleDl2K+BZsK7PB6AZUy29dch/7bqqR9CChYjvOtU+0oj/4OG5rdcGVeNOiWgWjzBYImg+NNtJq32smfzz43MIPa76v3P3ifdqBhARRldWzhxv3L13/jVbhkarHli6mqeb8VXrBl510dgnTzY+9q3jC3GiPYWSl4qhHcstmcsrgNVK5M5jnVYiIuhqiVgUyCOUfQo91GO5b7r7qvXVikczXU4YAHaOhOcN+d+ZiaY7+lgzeem6yjkDAYBIIxZxoyNELIsxbxsK1vR5WJIYMtOON05W3rNjqOoTERLGHcdbb7h76qHDjduO1n56U80s6YsSLinaNVq+R8uDx1u37lt885YBALun2/cdbaqBINLSTThKGIKKh4pPKKmvHlo80YiHQh+K3GpVvOeayXufnvvu8cZCVysSKvnGwTIfoiUy2AvW8VZy96kOC65YGb5xUy1m8QikaDHifzzY/PzB1v3T3a2D/lBJ7a8bO4ttw8HFK8KvHGtPdVAO1DUTJY/smNmM8sj66DRUUp/d31xRamuxbudUO/mZcwcuHQ0FxIKIuepTInKioc8dDC4bKw1WvHpL12MTDxaIxAICXr2l/yO7w7mZzq//x6l/3Dff76nHZztJpDcPlD903eqLRittzSIYKqnbDyz+5lcO7z/e/OS3pwFBzU+0HdhuHi7/zAtXv+df9s014tFaYFZiWklw/53Vg+9o+fTexn3H2ztXll63oVqgQNV72WTls/saXzvRaSby9HxyuqMXYwbgEa5ZXf78kebuY9FbttZ2jZbMd062k9m5+HgzEaCT8JFGUo/5Hw40FyJOXBRZz3cvHSldOhoeayaYjY7Xky7L43PRp/bVP/7jo+1EFuYjmosWkiRhnFpMaKZ7pJEAuGK88qkb1rz7GyfPTLe/8kxDQbSAouTHLxl9zabBvDv51hes+Op3T//L3cc++s3j5eESLXTb852W7Wi88/LVtz02fe9DU61agJlWq530iuGzMGvrYHDLJUM7R8ON/UE7kc/ub3xruvuTG6svW1s9fzj8wK7h4y09EKpLRkMPtGXADqkuWVH6jQsGn5yPbt7UV/UJgCK8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";
				    }
				    else if(e.target.value[0]==4){
				    	inputCard.maxLength = 19;
				    	card = "visa";
				    	document.querySelector(".brand-card").style.display = "inherit";
				    	document.querySelector(".brand-card").src = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAGQAAABkCAIAAAD/gAIDAAABN2lDQ1BBZG9iZSBSR0IgKDE5OTgpAAAokZWPv0rDUBSHvxtFxaFWCOLgcCdRUGzVwYxJW4ogWKtDkq1JQ5ViEm6uf/oQjm4dXNx9AidHwUHxCXwDxamDQ4QMBYvf9J3fORzOAaNi152GUYbzWKt205Gu58vZF2aYAoBOmKV2q3UAECdxxBjf7wiA10277jTG+38yH6ZKAyNguxtlIYgK0L/SqQYxBMygn2oQD4CpTto1EE9AqZf7G1AKcv8ASsr1fBBfgNlzPR+MOcAMcl8BTB1da4Bakg7UWe9Uy6plWdLuJkEkjweZjs4zuR+HiUoT1dFRF8jvA2AxH2w3HblWtay99X/+PRHX82Vun0cIQCw9F1lBeKEuf1UYO5PrYsdwGQ7vYXpUZLs3cLcBC7dFtlqF8hY8Dn8AwMZP/fNTP8gAAAAJcEhZcwAACxMAAAsTAQCanBgAAAYGaVRYdFhNTDpjb20uYWRvYmUueG1wAAAAAAA8P3hwYWNrZXQgYmVnaW49Iu+7vyIgaWQ9Ilc1TTBNcENlaGlIenJlU3pOVGN6a2M5ZCI/PiA8eDp4bXBtZXRhIHhtbG5zOng9ImFkb2JlOm5zOm1ldGEvIiB4OnhtcHRrPSJBZG9iZSBYTVAgQ29yZSA1LjYtYzE0OCA3OS4xNjQwMzYsIDIwMTkvMDgvMTMtMDE6MDY6NTcgICAgICAgICI+IDxyZGY6UkRGIHhtbG5zOnJkZj0iaHR0cDovL3d3dy53My5vcmcvMTk5OS8wMi8yMi1yZGYtc3ludGF4LW5zIyI+IDxyZGY6RGVzY3JpcHRpb24gcmRmOmFib3V0PSIiIHhtbG5zOnhtcD0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wLyIgeG1sbnM6ZGM9Imh0dHA6Ly9wdXJsLm9yZy9kYy9lbGVtZW50cy8xLjEvIiB4bWxuczpwaG90b3Nob3A9Imh0dHA6Ly9ucy5hZG9iZS5jb20vcGhvdG9zaG9wLzEuMC8iIHhtbG5zOnhtcE1NPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvbW0vIiB4bWxuczpzdEV2dD0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL3NUeXBlL1Jlc291cmNlRXZlbnQjIiB4bXA6Q3JlYXRlRGF0ZT0iMjAxOC0wMS0wOVQxNzo0MjoxNC0wNTowMCIgeG1wOk1vZGlmeURhdGU9IjIwMjItMDgtMjZUMTU6MTk6NDAtMDU6MDAiIHhtcDpNZXRhZGF0YURhdGU9IjIwMjItMDgtMjZUMTU6MTk6NDAtMDU6MDAiIHhtcDpDcmVhdG9yVG9vbD0iQWRvYmUgUGhvdG9zaG9wIENDIDIwMTcgKFdpbmRvd3MpIiBkYzpmb3JtYXQ9ImltYWdlL3BuZyIgcGhvdG9zaG9wOkNvbG9yTW9kZT0iMyIgcGhvdG9zaG9wOklDQ1Byb2ZpbGU9IkFkb2JlIFJHQiAoMTk5OCkiIHhtcE1NOkluc3RhbmNlSUQ9InhtcC5paWQ6MWZjMTMwOTctZGM4Ny0yMDQ4LWFkMzgtZGVmZjg2YmRkN2E4IiB4bXBNTTpEb2N1bWVudElEPSJhZG9iZTpkb2NpZDpwaG90b3Nob3A6ODQwMjAyMzEtYmJkMi1iZjQ5LTg4ODctMDFiNmNkODljMGM0IiB4bXBNTTpPcmlnaW5hbERvY3VtZW50SUQ9InhtcC5kaWQ6NTQxNTgwNDktNzRhOS0zODQxLWJjNDYtMWFiMzAzZmRmMDhlIj4gPHhtcE1NOkhpc3Rvcnk+IDxyZGY6U2VxPiA8cmRmOmxpIHN0RXZ0OmFjdGlvbj0ic2F2ZWQiIHN0RXZ0Omluc3RhbmNlSUQ9InhtcC5paWQ6NTQxNTgwNDktNzRhOS0zODQxLWJjNDYtMWFiMzAzZmRmMDhlIiBzdEV2dDp3aGVuPSIyMDE4LTAxLTA5VDE3OjQ4OjA1LTA1OjAwIiBzdEV2dDpzb2Z0d2FyZUFnZW50PSJBZG9iZSBQaG90b3Nob3AgQ0MgMjAxNyAoV2luZG93cykiIHN0RXZ0OmNoYW5nZWQ9Ii8iLz4gPHJkZjpsaSBzdEV2dDphY3Rpb249InNhdmVkIiBzdEV2dDppbnN0YW5jZUlEPSJ4bXAuaWlkOjFmYzEzMDk3LWRjODctMjA0OC1hZDM4LWRlZmY4NmJkZDdhOCIgc3RFdnQ6d2hlbj0iMjAyMi0wOC0yNlQxNToxOTo0MC0wNTowMCIgc3RFdnQ6c29mdHdhcmVBZ2VudD0iQWRvYmUgUGhvdG9zaG9w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";
				    }
				    else if((e.target.value[0]+e.target.value[1]>=51 && e.target.value[0]+e.target.value[1]<=55) || (e.target.value[0]+e.target.value[1]+e.target.value[2]+e.target.value[3]>=2221 && e.target.value[0]+e.target.value[1]+e.target.value[2]+e.target.value[3]<=2720)) {
				    	card = "master";
				    	inputCard.maxLength = 19;
				    	document.querySelector(".brand-card").style.display = "inherit";
				    	document.querySelector(".brand-card").src = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAGQAAABkCAIAAAD/gAIDAAABN2lDQ1BBZG9iZSBSR0IgKDE5OTgpAAAokZWPv0rDUBSHvxtFxaFWCOLgcCdRUGzVwYxJW4ogWKtDkq1JQ5ViEm6uf/oQjm4dXNx9AidHwUHxCXwDxamDQ4QMBYvf9J3fORzOAaNi152GUYbzWKt205Gu58vZF2aYAoBOmKV2q3UAECdxxBjf7wiA10277jTG+38yH6ZKAyNguxtlIYgK0L/SqQYxBMygn2oQD4CpTto1EE9AqZf7G1AKcv8ASsr1fBBfgNlzPR+MOcAMcl8BTB1da4Bakg7UWe9Uy6plWdLuJkEkjweZjs4zuR+HiUoT1dFRF8jvA2AxH2w3HblWtay99X/+PRHX82Vun0cIQCw9F1lBeKEuf1UYO5PrYsdwGQ7vYXpUZLs3cLcBC7dFtlqF8hY8Dn8AwMZP/fNTP8gAAAAJcEhZcwAACxMAAAsTAQCanBgAAAYGaVRYdFhNTDpjb20uYWRvYmUueG1wAAAAAAA8P3hwYWNrZXQgYmVnaW49Iu+7vyIgaWQ9Ilc1TTBNcENlaGlIenJlU3pOVGN6a2M5ZCI/PiA8eDp4bXBtZXRhIHhtbG5zOng9ImFkb2JlOm5zOm1ldGEvIiB4OnhtcHRrPSJBZG9iZSBYTVAgQ29yZSA1LjYtYzE0OCA3OS4xNjQwMzYsIDIwMTkvMDgvMTMtMDE6MDY6NTcgICAgICAgICI+IDxyZGY6UkRGIHhtbG5zOnJkZj0iaHR0cDovL3d3dy53My5vcmcvMTk5OS8wMi8yMi1yZGYtc3ludGF4LW5zIyI+IDxyZGY6RGVzY3JpcHRpb24gcmRmOmFib3V0PSIiIHhtbG5zOnhtcD0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wLyIgeG1sbnM6ZGM9Imh0dHA6Ly9wdXJsLm9yZy9kYy9lbGVtZW50cy8xLjEvIiB4bWxuczpwaG90b3Nob3A9Imh0dHA6Ly9ucy5hZG9iZS5jb20vcGhvdG9zaG9wLzEuMC8iIHhtbG5zOnhtcE1NPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvbW0vIiB4bWxuczpzdEV2dD0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL3NUeXBlL1Jlc291cmNlRXZlbnQjIiB4bXA6Q3JlYXRlRGF0ZT0iMjAxOC0wMS0wOVQxNzo0MjoxNC0wNTowMCIgeG1wOk1vZGlmeURhdGU9IjIwMjItMDgtMjZUMTU6MjE6MDItMDU6MDAiIHhtcDpNZXRhZGF0YURhdGU9IjIwMjItMDgtMjZUMTU6MjE6MDItMDU6MDAiIHhtcDpDcmVhdG9yVG9vbD0iQWRvYmUgUGhvdG9zaG9wIENDIDIwMTcgKFdpbmRvd3MpIiBkYzpmb3JtYXQ9ImltYWdlL3BuZyIgcGhvdG9zaG9wOkNvbG9yTW9kZT0iMyIgcGhvdG9zaG9wOklDQ1Byb2ZpbGU9IkFkb2JlIFJHQiAoMTk5OCkiIHhtcE1NOkluc3RhbmNlSUQ9InhtcC5paWQ6OTQ1MDhiNGItNjkxMy1kYTQzLTgyYTgtYWIyNjliZDg1NjVlIiB4bXBNTTpEb2N1bWVudElEPSJhZG9iZTpkb2NpZDpwaG90b3Nob3A6OTA4YmZjNzMtYjU4YS04ODRlLTkxZmUtOGY4N2I1Nzc4N2NjIiB4bXBNTTpPcmlnaW5hbERvY3VtZW50SUQ9InhtcC5kaWQ6NTQxNTgwNDktNzRhOS0zODQxLWJjNDYtMWFiMzAzZmRmMDhlIj4gPHhtcE1NOkhpc3Rvcnk+IDxyZGY6U2VxPiA8cmRmOmxpIHN0RXZ0OmFjdGlvbj0ic2F2ZWQiIHN0RXZ0Omluc3RhbmNlSUQ9InhtcC5paWQ6NTQxNTgwNDktNzRhOS0zODQxLWJjNDYtMWFiMzAzZmRmMDhlIiBzdEV2dDp3aGVuPSIyMDE4LTAxLTA5VDE3OjQ4OjA1LTA1OjAwIiBzdEV2dDpzb2Z0d2FyZUFnZW50PSJBZG9iZSBQaG90b3Nob3AgQ0MgMjAxNyAoV2luZG93cykiIHN0RXZ0OmNoYW5nZWQ9Ii8iLz4gPHJkZjpsaSBzdEV2dDphY3Rpb249InNhdmVkIiBzdEV2dDppbnN0YW5jZUlEPSJ4bXAuaWlkOjk0NTA4YjRiLTY5MTMtZGE0My04MmE4LWFiMjY5YmQ4NTY1ZSIgc3RFdnQ6d2hlbj0iMjAyMi0wOC0yNlQxNToyMTowMi0wNTowMCIgc3RFdnQ6c29mdHdhcmVBZ2VudD0iQWRvYmUgUGhvdG9zaG9w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";
				    }
				    else{
				    	card = "";
				    	document.querySelector(".brand-card").style.display = "none";
				    }
				});
			</script>
		';
		return str_replace(array("\n", "\t"), "", $html);
	}

}