<?php
	/* * *****************************************************************************
	 * file: Cryption.php
	 * @autor: Thorn sereyvong
	 * @date: 25-03-2015
	 * ZOBENZ TEAM
	 * Description: For Encrypt and Descrypt data 
	 * ***************************************************************************** */
	Class Cryption{
		private $key;
		private $key_size;
		private $iv_size;
		private $iv;
		
		public function __construct(){
			$this->key = base64_encode("zobenz@vong");
			$this->key_size = strlen($this->key);
			$this->iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
			$this->iv = mcrypt_create_iv($this->iv_size, MCRYPT_RAND);
		}
		public function IEncrypt($str){
			$ciphertext = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $this->key,$str, MCRYPT_MODE_CBC, $this->iv);
			$ciphertext = $this->iv.$ciphertext;
			return trim($this->ISubStr(base64_encode($ciphertext),1));
		}
		public function IDecrypt($str){
			$ciphertext_dec = base64_decode($this->ISubStr($str,0));
			$iv_dec = substr($ciphertext_dec, 0, $this->iv_size);
			$ciphertext_dec = substr($ciphertext_dec, $this->iv_size);
			return trim(mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $this->key,$ciphertext_dec, MCRYPT_MODE_CBC, $iv_dec));
		}
		public function ISubStr($str,$option){
			if($option==1) 
				return substr($str, 5,15).substr($str, 0,5).substr($str, 37,7).substr($str, 16,21);
			return substr($str, 15,5).substr($str, 0,15).substr($str, 31,21).substr($str, 20,7);
		}
		public function IMD5($str){
			return substr(md5($str), 5,15);
		}
	}