// Generic X509TrustManager override — accept all server certificates.
Java.perform(function () {
  var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
  var SSLContext = Java.use('javax.net.ssl.SSLContext');

  var TrustManager = Java.registerClass({
    name: 'com.reveng.TrustAllManager',
    implements: [X509TrustManager],
    methods: {
      checkClientTrusted: function (chain, authType) {},
      checkServerTrusted: function (chain, authType) {},
      getAcceptedIssuers: function () { return []; }
    }
  });

  var TrustManagers = [TrustManager.$new()];
  var ctx = SSLContext.getInstance('TLS');
  ctx.init(null, TrustManagers, null);
  SSLContext.setDefault(ctx);
  console.log('[unpin] X509TrustManager override installed');
});
