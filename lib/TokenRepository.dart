import 'dart:async';
import 'package:arcgis_maps/arcgis_maps.dart';

class TokenRepository implements ArcGISAuthenticationChallengeHandler {
  final OAuthUserConfiguration _oAuthUserConfiguration;

  TokenRepository({required OAuthUserConfiguration oAuthUserConfiguration})
      : _oAuthUserConfiguration = oAuthUserConfiguration {
    ArcGISEnvironment
        .authenticationManager.arcGISAuthenticationChallengeHandler = this;
  }

  /// Requests OAuth token via ArcGIS Flutter SDK
  Future<String> getToken() async {
    print("in getToken()");

    var portalUri = _oAuthUserConfiguration.portalUri;

    OAuthUserCredential oauthCredential;
    var credential = ArcGISEnvironment
        .authenticationManager.arcGISCredentialStore
        .getCredential(uri: portalUri);

    try {
      if (credential != null) {
        print("Get cached credentials");
        oauthCredential = credential as OAuthUserCredential;
      } else {
        print("Creating credentials");
        oauthCredential = await OAuthUserCredential.create(
            configuration: _oAuthUserConfiguration);
        ArcGISEnvironment.authenticationManager.arcGISCredentialStore
            .add(credential: oauthCredential);
      }

      var tokenInfo = await oauthCredential.getTokenInfo();

      var token = tokenInfo.accessToken;

      return token;
    } catch (e, stackTrace) {
      return "<EMPTY_TOKEN>";
    }
  }


  final _completers = <Completer<String>>[];

  /// Requests OAuth token concurrently via ArcGIS Flutter SDK
  Future<String> getTokenConcurrently() async {
    print("in getToken()");
    Completer<String> completer = Completer();
    _completers.add(completer);
    if (_completers.length > 1) return completer.future;

    // ^^^^ we do not need to execute the code below this line for more than one time

    var portalUri = _oAuthUserConfiguration.portalUri;

    OAuthUserCredential oauthCredential;
    var credential = ArcGISEnvironment
        .authenticationManager.arcGISCredentialStore
        .getCredential(uri: portalUri);

    try {
      if (credential != null) {
        print("Get cached credentials");
        oauthCredential = credential as OAuthUserCredential;
      } else {
        print("Creating credentials");
        oauthCredential = await OAuthUserCredential.create(
            configuration: _oAuthUserConfiguration);
        ArcGISEnvironment.authenticationManager.arcGISCredentialStore
            .add(credential: oauthCredential);
      }

      var tokenInfo = await oauthCredential.getTokenInfo();

      var token = tokenInfo.accessToken;

      for (var c in _completers) {
        c.complete(token);
      }
    } catch (e, stackTrace) {
      for (var c in _completers) {
        c.completeError(e, stackTrace);
      }
    }

    _completers.clear();

    return completer.future;
  }

  void signOut() async {
    ArcGISEnvironment
        .authenticationManager.arcGISAuthenticationChallengeHandler = null;

    // Revoke OAuth tokens and remove all credentials to log out.
    await Future.wait(
      ArcGISEnvironment.authenticationManager.arcGISCredentialStore
          .getCredentials()
          .whereType<OAuthUserCredential>()
          .map((credential) => credential.revokeToken()),
    );
    ArcGISEnvironment.authenticationManager.arcGISCredentialStore.removeAll();
  }

  @override
  void handleArcGISAuthenticationChallenge(
      ArcGISAuthenticationChallenge challenge) async {
    try {
      // Initiate the sign in process to the OAuth server using the defined user configuration.
      final credential = await OAuthUserCredential.create(
        configuration: _oAuthUserConfiguration,
      );

      // Sign in was successful, so continue with the provided credential.
      challenge.continueWithCredential(credential);
    } on ArcGISException catch (error) {
      // Sign in was canceled, or there was some other error.
      final e = (error.wrappedException as ArcGISException?) ?? error;
      if (e.errorType == ArcGISExceptionType.commonUserCanceled) {
        challenge.cancel();
      } else {
        challenge.continueAndFail();
      }
    }
  }
}
