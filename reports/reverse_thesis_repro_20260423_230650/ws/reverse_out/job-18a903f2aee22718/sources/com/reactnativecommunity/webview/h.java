package com.reactnativecommunity.webview;

import android.graphics.Bitmap;
import android.net.http.SslError;
import android.os.Build;
import android.os.SystemClock;
import android.util.Log;
import android.webkit.CookieManager;
import android.webkit.HttpAuthHandler;
import android.webkit.RenderProcessGoneDetail;
import android.webkit.SslErrorHandler;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.uimanager.H0;
import com.reactnativecommunity.webview.e;
import com.reactnativecommunity.webview.n;
import g2.C0535b;
import g2.C0536c;
import g2.C0537d;
import g2.C0539f;
import g2.C0542i;
import g2.C0543j;
import java.util.concurrent.atomic.AtomicReference;

/* JADX INFO: loaded from: classes.dex */
public class h extends WebViewClient {

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private static String f8607e = "RNCWebViewClient";

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    protected boolean f8608a = false;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    protected e.d f8609b = null;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    protected String f8610c = null;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    protected a f8611d = null;

    protected WritableMap a(WebView webView, String str) {
        WritableMap writableMapCreateMap = Arguments.createMap();
        writableMapCreateMap.putDouble("target", q.a(webView));
        writableMapCreateMap.putString("url", str);
        writableMapCreateMap.putBoolean("loading", (this.f8608a || webView.getProgress() == 100) ? false : true);
        writableMapCreateMap.putString("title", webView.getTitle());
        writableMapCreateMap.putBoolean("canGoBack", webView.canGoBack());
        writableMapCreateMap.putBoolean("canGoForward", webView.canGoForward());
        return writableMapCreateMap;
    }

    protected void b(WebView webView, String str) {
        int iA = q.a(webView);
        H0.c((ReactContext) webView.getContext(), iA).g(new C0537d(iA, a(webView, str)));
    }

    public void c(a aVar) {
        this.f8611d = aVar;
    }

    public void d(String str) {
        this.f8610c = str;
    }

    @Override // android.webkit.WebViewClient
    public void doUpdateVisitedHistory(WebView webView, String str, boolean z3) {
        super.doUpdateVisitedHistory(webView, str, z3);
        ((e) webView).g(webView, new C0539f(q.a(webView), a(webView, str)));
    }

    public void e(e.d dVar) {
        this.f8609b = dVar;
    }

    @Override // android.webkit.WebViewClient
    public void onPageFinished(WebView webView, String str) {
        super.onPageFinished(webView, str);
        if (CookieManager.getInstance().getCookie(str) != null) {
            CookieManager.getInstance().flush();
        }
        if (this.f8608a) {
            return;
        }
        ((e) webView).a();
        b(webView, str);
    }

    @Override // android.webkit.WebViewClient
    public void onPageStarted(WebView webView, String str, Bitmap bitmap) {
        super.onPageStarted(webView, str, bitmap);
        this.f8608a = false;
        ((e) webView).b();
    }

    @Override // android.webkit.WebViewClient
    public void onReceivedError(WebView webView, int i3, String str, String str2) {
        String str3 = this.f8610c;
        if (str3 != null && str2.equals(str3) && i3 == -1 && str.equals("net::ERR_FAILED")) {
            d(null);
            return;
        }
        super.onReceivedError(webView, i3, str, str2);
        this.f8608a = true;
        b(webView, str2);
        WritableMap writableMapA = a(webView, str2);
        writableMapA.putDouble("code", i3);
        writableMapA.putString("description", str);
        int iA = q.a(webView);
        H0.c((ReactContext) webView.getContext(), iA).g(new C0536c(iA, writableMapA));
    }

    @Override // android.webkit.WebViewClient
    public void onReceivedHttpAuthRequest(WebView webView, HttpAuthHandler httpAuthHandler, String str, String str2) {
        a aVar = this.f8611d;
        if (aVar != null) {
            httpAuthHandler.proceed(aVar.f8553a, aVar.f8554b);
        } else {
            super.onReceivedHttpAuthRequest(webView, httpAuthHandler, str, str2);
        }
    }

    @Override // android.webkit.WebViewClient
    public void onReceivedHttpError(WebView webView, WebResourceRequest webResourceRequest, WebResourceResponse webResourceResponse) {
        super.onReceivedHttpError(webView, webResourceRequest, webResourceResponse);
        if (webResourceRequest.isForMainFrame()) {
            WritableMap writableMapA = a(webView, webResourceRequest.getUrl().toString());
            writableMapA.putInt("statusCode", webResourceResponse.getStatusCode());
            writableMapA.putString("description", webResourceResponse.getReasonPhrase());
            int iA = q.a(webView);
            H0.c((ReactContext) webView.getContext(), iA).g(new C0535b(iA, writableMapA));
        }
    }

    @Override // android.webkit.WebViewClient
    public void onReceivedSslError(WebView webView, SslErrorHandler sslErrorHandler, SslError sslError) {
        String url = webView.getUrl();
        String url2 = sslError.getUrl();
        sslErrorHandler.cancel();
        if (!url.equalsIgnoreCase(url2)) {
            Log.w(f8607e, "Resource blocked from loading due to SSL error. Blocked URL: " + url2);
            return;
        }
        int primaryError = sslError.getPrimaryError();
        onReceivedError(webView, primaryError, "SSL error: " + (primaryError != 0 ? primaryError != 1 ? primaryError != 2 ? primaryError != 3 ? primaryError != 4 ? primaryError != 5 ? "Unknown SSL Error" : "A generic error occurred" : "The date of the certificate is invalid" : "The certificate authority is not trusted" : "Hostname mismatch" : "The certificate has expired" : "The certificate is not yet valid"), url2);
    }

    @Override // android.webkit.WebViewClient
    public boolean onRenderProcessGone(WebView webView, RenderProcessGoneDetail renderProcessGoneDetail) {
        if (Build.VERSION.SDK_INT < 26) {
            return false;
        }
        super.onRenderProcessGone(webView, renderProcessGoneDetail);
        if (renderProcessGoneDetail.didCrash()) {
            Log.e(f8607e, "The WebView rendering process crashed.");
        } else {
            Log.w(f8607e, "The WebView rendering process was killed by the system.");
        }
        if (webView == null) {
            return true;
        }
        WritableMap writableMapA = a(webView, webView.getUrl());
        writableMapA.putBoolean("didCrash", renderProcessGoneDetail.didCrash());
        int iA = q.a(webView);
        H0.c((ReactContext) webView.getContext(), iA).g(new C0542i(iA, writableMapA));
        return true;
    }

    @Override // android.webkit.WebViewClient
    public boolean shouldOverrideUrlLoading(WebView webView, String str) {
        e eVar = (e) webView;
        if (eVar.getReactApplicationContext().getJavaScriptContextHolder().get() == 0 || eVar.f8580j == null) {
            Y.a.I(f8607e, "Couldn't use blocking synchronous call for onShouldStartLoadWithRequest due to debugging or missing Catalyst instance, falling back to old event-and-load.");
            this.f8609b.b(true);
            int iA = q.a(webView);
            H0.c((ReactContext) webView.getContext(), iA).g(new C0543j(iA, a(webView, str)));
            return true;
        }
        q.d dVarB = n.f8646g.b();
        Double d3 = (Double) dVarB.f9844a;
        double dDoubleValue = d3.doubleValue();
        AtomicReference atomicReference = (AtomicReference) dVarB.f9845b;
        WritableMap writableMapA = a(webView, str);
        writableMapA.putDouble("lockIdentifier", dDoubleValue);
        eVar.f(writableMapA);
        try {
            synchronized (atomicReference) {
                try {
                    long jElapsedRealtime = SystemClock.elapsedRealtime();
                    while (atomicReference.get() == n.d.a.UNDECIDED) {
                        if (SystemClock.elapsedRealtime() - jElapsedRealtime > 250) {
                            Y.a.I(f8607e, "Did not receive response to shouldOverrideUrlLoading in time, defaulting to allow loading.");
                            n.f8646g.c(d3);
                            return false;
                        }
                        atomicReference.wait(250L);
                    }
                    boolean z3 = atomicReference.get() == n.d.a.SHOULD_OVERRIDE;
                    n.f8646g.c(d3);
                    return z3;
                } catch (Throwable th) {
                    throw th;
                }
            }
        } catch (InterruptedException e3) {
            Y.a.n(f8607e, "shouldOverrideUrlLoading was interrupted while waiting for result.", e3);
            n.f8646g.c(d3);
            return false;
        }
    }

    @Override // android.webkit.WebViewClient
    public boolean shouldOverrideUrlLoading(WebView webView, WebResourceRequest webResourceRequest) {
        return shouldOverrideUrlLoading(webView, webResourceRequest.getUrl().toString());
    }
}
