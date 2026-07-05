// TrustKit pinning bypass — disable TSKPinningValidator evaluation.
Java.perform(function () {
  try {
    var TrustKit = Java.use('com.datatheorem.android.trustkit.TrustKit');
    TrustKit.getInstance.overload().implementation = function () {
      var inst = this.getInstance();
      return inst;
    };
  } catch (e) {
    console.log('[unpin] TrustKit class not found: ' + e);
  }
  try {
    var Validator = Java.use('com.datatheorem.android.trustkit.pinning.TSKPinningValidator');
    Validator.evaluateTrust.overload('java.security.cert.X509Certificate', 'java.lang.String').implementation = function (cert, domain) {
      console.log('[unpin] TrustKit evaluateTrust bypassed for ' + domain);
      return;
    };
  } catch (e2) {
    console.log('[unpin] TSKPinningValidator hook failed: ' + e2);
  }
});
