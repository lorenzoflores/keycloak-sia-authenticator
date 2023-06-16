package es.sescam.keycloak.sia;

import lombok.extern.slf4j.Slf4j;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.ConfigurableAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Arrays;
import java.util.List;

/**
 * @author Lorenzo Flores Sánchez
 */
@Slf4j
public class SIAAuthenticatorFactory implements AuthenticatorFactory, ConfigurableAuthenticatorFactory {

	public static final String PROVIDER_ID = "sia-authenticator";

	private static final Authenticator SINGLETON = new SIAAuthenticator();

	@Override
	public Authenticator create(KeycloakSession session) {
		return SINGLETON;
	}

	@Override
	public String getDisplayType() {
		return "SIA Authenticator";
	}

	@Override
	public String getReferenceCategory() {
		return "sescam";
	}

	@Override
	public boolean isConfigurable() {
		return true;
	}

	@Override
	public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
		return REQUIREMENT_CHOICES;
	}

	@Override
	public boolean isUserSetupAllowed() {
		return false;
	}

	@Override
	public String getHelpText() {
		return getDisplayType();
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		
		ProviderConfigProperty pathFileConfig = new ProviderConfigProperty();
	    pathFileConfig.setType(ProviderConfigProperty.STRING_TYPE);
	    pathFileConfig.setName(SIAAuthenticator.PATH_FILE_CONFIG_PROPERTY);
	    pathFileConfig.setLabel("File config path");
	    pathFileConfig.setHelpText(
	        "Absolute path to gatewayapi.properties.");
	    pathFileConfig.setDefaultValue("/opt/sia/gatewayapi-default.properties");

	    ProviderConfigProperty language = new ProviderConfigProperty();
	    language.setType(ProviderConfigProperty.STRING_TYPE);
	    language.setName(SIAAuthenticator.LANGUAJE_CONFIG_PROPERTY);
	    language.setLabel("Language preference");
	    language.setHelpText("Set the prefered platform language.");
	    language.setDefaultValue("es");

	    ProviderConfigProperty authLevel = new ProviderConfigProperty();
	    authLevel.setType(ProviderConfigProperty.STRING_TYPE);
	    authLevel.setName(SIAAuthenticator.AUTHENTICATION_LEVEL_CONFIG_PROPERTY);
	    authLevel.setLabel("Authentication Level");
	    authLevel.setHelpText("Set de authentication level: 1 = password only 2 = OTP only 3 = password + OTP)");
	    authLevel.setDefaultValue("1");

	    return Arrays.asList(pathFileConfig, language, authLevel);
	}

	@Override
	public void init(Config.Scope config) {
	}

	@Override
	public void postInit(KeycloakSessionFactory factory) {
	}

	@Override
	public void close() {
	}

	@Override
	public String getId() {
		return PROVIDER_ID;
	}

}
