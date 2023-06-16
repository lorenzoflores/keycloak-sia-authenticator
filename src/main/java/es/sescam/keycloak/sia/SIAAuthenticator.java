package es.sescam.keycloak.sia;

import lombok.extern.slf4j.Slf4j;

import org.checkerframework.common.returnsreceiver.qual.This;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Map;

import com.openlandsw.rss.gateway.DataAuthByLevelTransactionResult;
import com.openlandsw.rss.gateway.DataToAuth;
import com.openlandsw.rss.gateway.GateWayAPI;
import com.openlandsw.rss.gateway.StartAuthTransactionResult;


/**
 * @author Lorenzo Flores Sánchez
 */
@Slf4j
public class SIAAuthenticator implements Authenticator {

	
	public static final String PATH_FILE_CONFIG_PROPERTY = "ext-sescam-path-file";
	public static final String LANGUAJE_CONFIG_PROPERTY = "ext-sescam-language";
	public static final String AUTHENTICATION_LEVEL_CONFIG_PROPERTY = "ext-sescam-authentication-level";
	  
	private static final String SESSION_KEY = "sia-authenticator-key";
	private static final String TRANSACTION_KEY = "sia-transaction-key";
	private static final String QUERY_PARAM = "siakey";
	private static final String REDIRECT_TEMPLATE = "redirect-page.ftl";
	
	GateWayAPI api = null;

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		
		String sessionKey = context.getAuthenticationSession().getAuthNote(SESSION_KEY);
		if (sessionKey != null) {
			String requestKey = context.getHttpRequest().getUri().getQueryParameters().getFirst(QUERY_PARAM);
			if (requestKey != null) {
				if (requestKey.equals(sessionKey)) {
					
					//Recupero la transacción guardada
					String transactionId = context.getAuthenticationSession().getAuthNote(TRANSACTION_KEY);
					
					log.info("Comienza la obtención de datos de la  Autenticación del usuario con transaction id " + transactionId);

					 //Se recupera la transacción 
					try {
						DataAuthByLevelTransactionResult resultAuthRecover = api.dataAuthByLevelTransaction(transactionId);
						
						//Buscamos si el usuario está ya registrado en KeyCloak, si no lo creamos en la sesión
						UserModel user = KeycloakModelUtils.findUserByNameOrEmail(context.getSession(), context.getRealm(), "SESCAM_" + resultAuthRecover.getOwnerInfo().getDatoPersonal4().toUpperCase());
						if (user ==  null){
							//Crear un usuario con los datos obtenidos de los datos suministrados por SIA
							KeycloakSession session = context.getSession();
							RealmModel realm = context.getRealm();
							user = session.users().addUser(realm, "SESCAM_" + resultAuthRecover.getOwnerInfo().getDatoPersonal4().toUpperCase());
							user.setEmail(resultAuthRecover.getOwnerInfo().getEmail());
							user.setFirstName(resultAuthRecover.getOwnerInfo().getDatoPersonal1());
							user.setLastName(resultAuthRecover.getOwnerInfo().getDatoPersonal2() + " " + resultAuthRecover.getOwnerInfo().getDatoPersonal3());
							user.setEnabled(true);
							
						}	
					
						context.setUser(user);
						
						/* Información extra en el certificado 
						
						X509Certificate certUsedInAuth = null;

						CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

						InputStream in = new ByteArrayInputStream(resultAuthRecover.getCertificate());
						certUsedInAuth = (X509Certificate) certFactory.generateCertificate(in);

						log.info(certUsedInAuth.getSubjectDN().getName());
						*/

						log.info("Estado de la transacción:" + resultAuthRecover.getStateTransaction().getResult());

						//Se cierra la transacción.
						api.endTransaction(transactionId);


					} catch (Exception e) {
						log.error("Error al intentar obtener los datos de una autenticación con Pasarela");
						log.error(e.getMessage());
						context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
					}

					log.info("Finaliza la obtención de datos de la Autenticación");
					
					
					context.success();
				} else {
					context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
				}
			} else {
				redirectToSIA(context);
			}
		} else {
			redirectToSIA(context);
		}
	}

	@Override
	public void action(AuthenticationFlowContext context) {
	}

	private void redirectToSIA(AuthenticationFlowContext context) {
		
		
		
		RealmModel realm = context.getRealm();

		String key = KeycloakModelUtils.generateId();
		context.getAuthenticationSession().setAuthNote(SESSION_KEY, key);

		String link = KeycloakUriBuilder.fromUri(context.getRefreshExecutionUrl()).queryParam(QUERY_PARAM, key).build().toString();
		
		
		//Recuperamos los valores establecidos en la configuración del flow
		String path = "/opt/sia/gatewayapi-default.properties";
		String lang = "es";
		int level = 1;
		
	
		AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
		if (authenticatorConfig != null) {
			Map<String, String> config = authenticatorConfig.getConfig();
			
			if (config != null) {
				path = config.get(SIAAuthenticator.PATH_FILE_CONFIG_PROPERTY);
				lang = config.get(SIAAuthenticator.LANGUAJE_CONFIG_PROPERTY);
				level = Integer.valueOf(config.get(SIAAuthenticator.AUTHENTICATION_LEVEL_CONFIG_PROPERTY));
			}
		}

		//Inicia la transacción con SIA

		log.info("Comienza el Inicio de la Transacción con SIA");

		this.api = new GateWayAPI();
		api.setPathFileConfig(path);

		// Parametros de autenticación
		DataToAuth datatoauth = new DataToAuth();

		// Establecemos el idioma por defecto si el cliente no lo especifica	
		datatoauth.setLanguage(lang);

		// Establezco las URL de vuelta
		datatoauth.setRedirectOK(link);
		datatoauth.setRedirectError(link);

		/*
		 * Dejamos recaer en la pasarela la selección de certificado. La
		 * pasarela automáticamente elegirá el certificado de autenticación y lo
		 * utilizará
		 */
		byte[] cert = null;
		datatoauth.setCertificate(cert);

		StartAuthTransactionResult result = null;


		try {

			result = api.startAuthByLevelTransaction("", level, datatoauth, null);

			context.getAuthenticationSession().setAuthNote(TRANSACTION_KEY, result.getIdTransaction());
			
			log.info("Finaliza el Inicio de Transacción con SIA");
			
			context.challenge(context.form().setAttribute("url_redirect", result.getRedirect()).createForm(REDIRECT_TEMPLATE));

		} catch (Exception e) {
			log.error("Error al conectar con la pasarela SIA \n");
			log.error(e.getMessage());
			context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
		}

	}


	@Override
	public boolean requiresUser() {
		return false;
	}

	@Override
	public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
		return true;
	}

	@Override
	public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
	}

	@Override
	public void close() {
	}

}
