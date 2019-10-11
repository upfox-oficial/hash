<?php

	/*
	* fxProtect - https://fxprotect.upfox.com.br
	* version 1.0.0
	* author Silva, Flavio Augusto [flavio@upfox.com]
	* copyright Silva, Flavio 2017-2019
	* license Upfox, inc
	*/

	class fxProtect{
		
		protected static $text 		= null;
		protected static $flagscurt = false;
		protected static $base64	= true;
		protected static $secretKey = ["cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"];
		protected static $iniVector = ["cf83e1357eefb8bd"];
		protected static $hash 	  	= "";
		protected static $method 	= "";
		
		public static function getHash() {	
			return self::$hash;
		}
		public static function getKey() {
			return self::$secretKey;
		}
		public static function getMethod() {
			return self::$method;
		}
		public static function getAllHashs(){
			return openssl_get_md_methods();
		}
		public static function addBase64(){
			self::$base64 = true;
		}
		public static function removeBase64(){
			self::$base64 = false;
		}
		public static function getBase64(){
			return self::$base64;
		}
		public static function getAllMethods(){
			$method = openssl_get_cipher_methods();
			//ECB mode should be avoided
			$method = array_filter( $method, function($n) { return stripos($n,"ecb")===FALSE; } );
			//At least as early as Aug 2016, Openssl declared the following weak: RC2, RC4, DES, 3DES, MD5 based
			$method = array_filter( $method, function($c) { return stripos($c,"des")===FALSE; } );
			$method = array_filter( $method, function($c) { return stripos($c,"rc2")===FALSE; } );
			$method = array_filter( $method, function($c) { return stripos($c,"rc4")===FALSE; } );
			$method = array_filter( $method, function($c) { return stripos($c,"md5")===FALSE; } );
			return $method;
		}
		public static function setIv($iv, $width=16) {
			self::$iniVector = [];
			if(!is_array($iv)){
				array_push(
					self::$iniVector, 
					substr(
						hash(
							self::getHash(), $iv
						), 0, $width
					)
				);
			}else{
				foreach($iv as $ivKeys){
					array_push(
						self::$iniVector, 
						substr(
							hash(
								self::getHash(), $ivKeys
							), 0, $width
						)
					);
				}
			}
			
		}
		public static function getIv() {
			return self::$iniVector;
		}
		public static function setKey($sk) {
			self::$secretKey = [];
			
			
			if(!is_array($sk))
				array_push(
					self::$secretKey, 
					hash(
						self::getHash(), $sk
					)
				);
			else{
				foreach($sk as $skKeys){
					array_push(
						self::$secretKey, 
						hash(
							self::getHash(), $skKeys
						)
					);
				}
			}
		}
		public static function selectHash($hash = null){
			# Array contendo todos os HASHs disponíveis.
			$hashs = self::getAllHashs();
			# Se encontrar o Hash informado dentro do ARRAY retornará o mesmo para seleção
			foreach($hashs as $key => $value){
					
				if($hash===$value){
					self::$hash = $value;
					return $value;
					break;
				}
			}
			# Caso contráorio informará o SHA512 como valor padrão
			self::$hash = "sha512";
			return "sha512";
		}
		public static function selectMethod($method = null){
			# Array contendo todos os METHODs disponíveis.
			$methods = self::getAllMethods();
			# Se encontrar o Hash informado dentro do ARRAY retornará o mesmo para seleção
			foreach($methods as $key => $value){
					
				if($method===$value){
					return $value;
					break;
				}
			}
			# Caso contráorio informará o [AES-256-CBC] como valor padrão.
			return "AES-256-CBC";
		}
		public static function setText($text=null,$encrypt=false){
			if($encrypt){
				self::$flagscurt = true;
				self::$text = self::encrypt($text);
			}else{
				self::$flagscurt = false;
				self::$text = $text;
			}
		}
		public static function getText($decrypt=false){
			if($decrypt)
				return self::decrypt(self::$text);
			else
				return self::$text;
		}
		public static function encrypt($text="") {
			
			$encrypt = $text;

			# Primeira criptografia
			for($i=0;$i<count(self::getKey());$i++){
				# Segundo nível com bloco falso
				for($j=0;$j<count(self::getIv());$j++){
					$encrypt = openssl_encrypt($encrypt,self::getMethod(),self::getKey()[$i],0,self::getIv()[$j]);
				}
			}

			if(self::getBase64()){
				self::setText(base64_encode($encrypt));
				return base64_encode($encrypt);
			}else{
				self::setText($encrypt);
				return $encrypt;
			}
			
		}
		public static function decrypt($text="") {
			
			# Verificação do estatus da base64
			if(self::getBase64())
				$decrypt = base64_decode($text);
			else
				$decrypt = ($text);
			
			# Aplicação da técnica ::fxProtect::
			for($i=count(self::getKey());$i>0;$i--){
				# Segundo nível com bloco falso
				for($j=count(self::getIv());$j>0;$j--){
					$decrypt = openssl_decrypt($decrypt,self::getMethod(),self::getKey()[$i-1],0,self::getIv()[$j-1]);
				}
			}
			# Verificaçaõ = Comparação entre o texto original e o texto de saído criptografado
			if($text != self::encrypt($decrypt)){
				echo "<p class='error'>";
				echo "<span class='errorTitle'>Atenção: </span><span class='errorText'>ocorreu uma falha ao reverter a criptografia, verifique a chave e/ou o bloco de segurança.</span>";
				echo "</p>";
				die();
			}
			
			return ($decrypt);
		}
		public static function setMethods($h = "sha512", $m="AES-256-CBC"){
			# Definindo um tipo de Hash.
			self::$hash = self::selectHash($h);
			# Definindo um tipo de método.
			self::$method = self::selectMethod($m);
		}
		public static function viewData($data){
			
			print("<pre>");
			print_r($data);
			print("</pre>");
		}
		public static function analizerVar(){
			/* Preparando texto para apresentação agradável */
			$ext = self::getText();
			preg_match_all("/.{1,50}/",$ext,$ext);
			$ext = (is_array($ext))?$ext[0]:$ext;
			
			$export =[ 
				"iv"=>self::getIv(),
				"key"=>self::getKey(),
				"hash"=>self::getHash(),
				"method"=>self::getMethod(),
				"base64"=>(self::getBase64())?"true":"false",
				(self::$flagscurt)?"encrypt":"text"=>$ext,
				"decrypt"=>(!empty(self::getText()))?self::decrypt(self::getText()):""
			];

			return $export;
		}
		public static function init($iData=null){
			if(isset($iData["hash"]))
				self::$hash = self::selectHash($iData["hash"]);
			else
				self::selectHash();

			if(isset($iData["method"]))
				self::$method = self::selectMethod($iData["method"]);
			else
				self::$method = self::selectMethod();

			
			if(isset($iData["base64"])){
				if(preg_match_all("/^(t|true|ok|1|v|y|sim|yes|verdadeiro)$/i",$iData["base64"]))
					self::addBase64();
				else
					self::removeBase64();
			}

			if(isset($iData["iv"]))
				if(isset($iData["width"]) && is_numeric($iData["width"]))
					self::setIv($iData["iv"],$iData["width"]);
				else
					self::setIv($iData["iv"]);
			
			if(isset($iData["key"]))
				self::setKey($iData["key"]);
		
			if(isset($iData["text"]))
				self::setText($iData["text"]);
			if(isset($iData["encrypt"]))
				self::setText($iData["encrypt"],TRUE);

			return self::getText();
		}
	}

	
	fxProtect::init([
		"iv"=>["BRAZIL19","ANGRADOSREIS"], # Just block false
		"key"=>["7l4v10","4ugust0"], # Multi-keys
		"hash"=>"sha512", # Have other hashs
		"method"=>"AES-256-CBC", # Have other methods
		"encrypt"=>" # Text to encrypt
		<div style='background:black;color:red;padding:10px;'>
			Php - Ajuda
		</div>
		",
	]);

	fxProtect::viewData(fxProtect::analizerVar()); # Just feedback
?>
