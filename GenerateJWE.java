import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWT;


public class GenerateJWE implements Execution {

	public ExecutionResult execute(MessageContext messageContext, ExecutionContext executionContext) {
		
		try {
			// Your code here.
			
			String inputKey = messageContext.getVariable("rsaKey");
			RSAKey rsaKey = RSAKey.parse(inputKey);
			RSAEncrypter enc = new RSAEncrypter(rsaKey.toRSAPublicKey());
			
			JWEHeader jweHeader = new JWEHeader
								.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
								.keyID(rsaKey.getKeyID())
								.build();
					
			
			String Payload = messageContext.getVariable("jwsPayload");
			Payload jwsPayload = new Payload(Payload);
			
			JWEObject jweObject = new JWEObject(jweHeader, jwsPayload);
		
			jweObject.encrypt(enc);
			
			String jweString = jweObject.serialize();
			messageContext.setVariable("jweString", jweString);
			
            return ExecutionResult.SUCCESS;

		} catch (Exception e) {
			return ExecutionResult.ABORT;
		}
	}
}