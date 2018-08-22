
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;



public class AzureAPIUtil {

	public static String buildAzureAuthorizationToken(String id, String secret) {
		String base64Sign;

		// Set Token expire time
		LocalDateTime date = LocalDateTime.now().plusDays(1);
		String expiry = date.format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:'00.0000000Z'"));
		try {

			String string_to_sign = id + "\n" + expiry;

			Mac hmacSHA512 = Mac.getInstance("HmacSHA512");
			SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(), "HmacSHA512");
			hmacSHA512.init(secretKeySpec);

			byte[] digest = hmacSHA512.doFinal(string_to_sign.getBytes());

			base64Sign = Base64.encodeBase64String(digest);

		} catch (IllegalStateException | InvalidKeyException | NoSuchAlgorithmException ex) {
			throw new RuntimeException("Problemas calculando HMAC", ex);
		}

		return "SharedAccessSignature "+id+"&"+date.format(DateTimeFormatter.ofPattern("yyyyMMddHHmm"))+"&"+base64Sign;
	}
}
