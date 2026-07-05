// OkHttp CertificatePinner bypass — hooks check() to no-op.
Java.perform(function () {
  try {
    var CertPinner = Java.use('okhttp3.CertificatePinner');
    CertPinner.check.overload('java.lang.String', 'java.util.List').implementation = function (host, pins) {
      console.log('[unpin] OkHttp CertificatePinner.check bypassed for ' + host);
    };
  } catch (e) {
    console.log('[unpin] OkHttp hook failed: ' + e);
  }
});
