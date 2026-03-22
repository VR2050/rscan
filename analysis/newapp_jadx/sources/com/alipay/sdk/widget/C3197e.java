package com.alipay.sdk.widget;

import android.R;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.net.Uri;
import android.net.http.SslError;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.text.TextUtils;
import android.view.View;
import android.webkit.JsPromptResult;
import android.webkit.SslErrorHandler;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import java.lang.reflect.Method;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import p005b.p085c.p088b.p089a.p090h.C1353c;
import p005b.p085c.p088b.p098h.C1373a;
import p005b.p085c.p088b.p100j.C1383h;
import p005b.p085c.p088b.p101k.C1389f;
import p005b.p085c.p088b.p101k.RunnableC1387d;
import p005b.p085c.p088b.p101k.RunnableC1388e;
import p005b.p131d.p132a.p133a.C1499a;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: com.alipay.sdk.widget.e */
/* loaded from: classes.dex */
public class C3197e extends LinearLayout {

    /* renamed from: c */
    public static Handler f8697c = new Handler(Looper.getMainLooper());

    /* renamed from: e */
    public ImageView f8698e;

    /* renamed from: f */
    public TextView f8699f;

    /* renamed from: g */
    public ImageView f8700g;

    /* renamed from: h */
    public ProgressBar f8701h;

    /* renamed from: i */
    public WebView f8702i;

    /* renamed from: j */
    public final d f8703j;

    /* renamed from: k */
    public e f8704k;

    /* renamed from: l */
    public f f8705l;

    /* renamed from: m */
    public g f8706m;

    /* renamed from: n */
    public View.OnClickListener f8707n;

    /* renamed from: o */
    public final float f8708o;

    /* renamed from: com.alipay.sdk.widget.e$a */
    public class a implements View.OnClickListener {

        /* renamed from: com.alipay.sdk.widget.e$a$a, reason: collision with other inner class name */
        public class RunnableC5122a implements Runnable {

            /* renamed from: c */
            public final /* synthetic */ View f8710c;

            public RunnableC5122a(a aVar, View view) {
                this.f8710c = view;
            }

            @Override // java.lang.Runnable
            public void run() {
                this.f8710c.setEnabled(true);
            }
        }

        public a() {
        }

        @Override // android.view.View.OnClickListener
        public void onClick(View view) {
            g gVar = C3197e.this.f8706m;
            if (gVar != null) {
                view.setEnabled(false);
                C3197e.f8697c.postDelayed(new RunnableC5122a(this, view), 256L);
                C3197e c3197e = C3197e.this;
                if (view == c3197e.f8698e) {
                    C3196d c3196d = (C3196d) gVar;
                    synchronized (c3196d) {
                        c3196d.m3853i();
                    }
                } else if (view == c3197e.f8700g) {
                    synchronized (((C3196d) gVar)) {
                        c3197e.getWebView().reload();
                        c3197e.getRefreshButton().setVisibility(4);
                    }
                }
            }
        }
    }

    /* renamed from: com.alipay.sdk.widget.e$b */
    public class b extends WebChromeClient {
        public b() {
        }

        @Override // android.webkit.WebChromeClient
        public boolean onJsPrompt(WebView webView, String str, String str2, String str3, JsPromptResult jsPromptResult) {
            C3196d c3196d = (C3196d) C3197e.this.f8704k;
            synchronized (c3196d) {
                if (str2.startsWith("<head>") && str2.contains("sdk_result_code:")) {
                    c3196d.f8683e.runOnUiThread(new RunnableC1387d(c3196d));
                }
                jsPromptResult.cancel();
            }
            return true;
        }

        @Override // android.webkit.WebChromeClient
        public void onProgressChanged(WebView webView, int i2) {
            C3197e c3197e = C3197e.this;
            if (!c3197e.f8703j.f8714b) {
                c3197e.f8701h.setVisibility(8);
            } else {
                if (i2 > 90) {
                    c3197e.f8701h.setVisibility(4);
                    return;
                }
                if (c3197e.f8701h.getVisibility() == 4) {
                    C3197e.this.f8701h.setVisibility(0);
                }
                C3197e.this.f8701h.setProgress(i2);
            }
        }

        @Override // android.webkit.WebChromeClient
        public void onReceivedTitle(WebView webView, String str) {
            C3197e c3197e = C3197e.this;
            C3196d c3196d = (C3196d) c3197e.f8704k;
            synchronized (c3196d) {
                if (!str.startsWith("http") && !c3197e.getUrl().endsWith(str)) {
                    c3196d.f8690l.getTitle().setText(str);
                }
            }
        }
    }

    /* renamed from: com.alipay.sdk.widget.e$c */
    public class c extends WebViewClient {
        public c() {
        }

        @Override // android.webkit.WebViewClient
        public void onPageFinished(WebView webView, String str) {
            C3197e c3197e = C3197e.this;
            C3196d c3196d = (C3196d) c3197e.f8705l;
            synchronized (c3196d) {
                C1353c.m367h(c3196d.f8688j, "biz", "h5ldd", SystemClock.elapsedRealtime() + "|" + C1383h.m451o(str));
                c3197e.f8702i.loadUrl("javascript:window.prompt('<head>'+document.getElementsByTagName('html')[0].innerHTML+'</head>');(function() {\n    if (window.AlipayJSBridge) {\n        return\n    }\n\n    function alipayjsbridgeFunc(url) {\n        var iframe = document.createElement(\"iframe\");\n        iframe.style.width = \"1px\";\n        iframe.style.height = \"1px\";\n        iframe.style.display = \"none\";\n        iframe.src = url;\n        document.body.appendChild(iframe);\n        setTimeout(function() {\n            document.body.removeChild(iframe)\n        }, 100)\n    }\n    window.alipayjsbridgeSetTitle = function(title) {\n        document.title = title;\n        alipayjsbridgeFunc(\"alipayjsbridge://setTitle?title=\" + encodeURIComponent(title))\n    };\n    window.alipayjsbridgeRefresh = function() {\n        alipayjsbridgeFunc(\"alipayjsbridge://onRefresh?\")\n    };\n    window.alipayjsbridgeBack = function() {\n        alipayjsbridgeFunc(\"alipayjsbridge://onBack?\")\n    };\n    window.alipayjsbridgeExit = function(bsucc) {\n        alipayjsbridgeFunc(\"alipayjsbridge://onExit?bsucc=\" + bsucc)\n    };\n    window.alipayjsbridgeShowBackButton = function(bshow) {\n        alipayjsbridgeFunc(\"alipayjsbridge://showBackButton?bshow=\" + bshow)\n    };\n    window.AlipayJSBridge = {\n        version: \"2.0\",\n        addListener: addListener,\n        hasListener: hasListener,\n        callListener: callListener,\n        callNativeFunc: callNativeFunc,\n        callBackFromNativeFunc: callBackFromNativeFunc\n    };\n    var uniqueId = 1;\n    var h5JsCallbackMap = {};\n\n    function iframeCall(paramStr) {\n        setTimeout(function() {\n        \tvar iframe = document.createElement(\"iframe\");\n        \tiframe.style.width = \"1px\";\n        \tiframe.style.height = \"1px\";\n        \tiframe.style.display = \"none\";\n        \tiframe.src = \"alipayjsbridge://callNativeFunc?\" + paramStr;\n        \tvar parent = document.body || document.documentElement;\n        \tparent.appendChild(iframe);\n        \tsetTimeout(function() {\n            \tparent.removeChild(iframe)\n        \t}, 0)\n        }, 0)\n    }\n\n    function callNativeFunc(nativeFuncName, data, h5JsCallback) {\n        var h5JsCallbackId = \"\";\n        if (h5JsCallback) {\n            h5JsCallbackId = \"cb_\" + (uniqueId++) + \"_\" + new Date().getTime();\n            h5JsCallbackMap[h5JsCallbackId] = h5JsCallback\n        }\n        var dataStr = \"\";\n        if (data) {\n            dataStr = encodeURIComponent(JSON.stringify(data))\n        }\n        var paramStr = \"func=\" + nativeFuncName + \"&cbId=\" + h5JsCallbackId + \"&data=\" + dataStr;\n        iframeCall(paramStr)\n    }\n\n    function callBackFromNativeFunc(h5JsCallbackId, data) {\n        var h5JsCallback = h5JsCallbackMap[h5JsCallbackId];\n        if (h5JsCallback) {\n            h5JsCallback(data);\n            delete h5JsCallbackMap[h5JsCallbackId]\n        }\n    }\n    var h5ListenerMap = {};\n\n    function addListener(jsFuncName, jsFunc) {\n        h5ListenerMap[jsFuncName] = jsFunc\n    }\n\n    function hasListener(jsFuncName) {\n        var jsFunc = h5ListenerMap[jsFuncName];\n        if (!jsFunc) {\n            return false\n        }\n        return true\n    }\n\n    function callListener(h5JsFuncName, data, nativeCallbackId) {\n        var responseCallback;\n        if (nativeCallbackId) {\n            responseCallback = function(responseData) {\n                var dataStr = \"\";\n                if (responseData) {\n                    dataStr = encodeURIComponent(JSON.stringify(responseData))\n                }\n                var paramStr = \"func=h5JsFuncCallback\" + \"&cbId=\" + nativeCallbackId + \"&data=\" + dataStr;\n                iframeCall(paramStr)\n            }\n        }\n        var h5JsFunc = h5ListenerMap[h5JsFuncName];\n        if (h5JsFunc) {\n            h5JsFunc(data, responseCallback)\n        } else if (h5JsFuncName == \"h5BackAction\") {\n            if (!window.alipayjsbridgeH5BackAction || !alipayjsbridgeH5BackAction()) {\n                var paramStr = \"func=back\";\n                iframeCall(paramStr)\n            }\n        } else {\n            console.log(\"AlipayJSBridge: no h5JsFunc \" + h5JsFuncName + data)\n        }\n    }\n    var event;\n    if (window.CustomEvent) {\n        event = new CustomEvent(\"alipayjsbridgeready\")\n    } else {\n        event = document.createEvent(\"Event\");\n        event.initEvent(\"alipayjsbridgeready\", true, true)\n    }\n    document.dispatchEvent(event);\n    setTimeout(excuteH5InitFuncs, 0);\n\n    function excuteH5InitFuncs() {\n        if (window.AlipayJSBridgeInitArray) {\n            var h5InitFuncs = window.AlipayJSBridgeInitArray;\n            delete window.AlipayJSBridgeInitArray;\n            for (var i = 0; i < h5InitFuncs.length; i++) {\n                try {\n                    h5InitFuncs[i](AlipayJSBridge)\n                } catch (e) {\n                    setTimeout(function() {\n                        throw e\n                    })\n                }\n            }\n        }\n    }\n})();\n;window.AlipayJSBridge.callListener('h5PageFinished');");
                WebView webView2 = c3197e.f8702i;
                if (webView2 != null) {
                    try {
                        webView2.resumeTimers();
                    } catch (Throwable unused) {
                    }
                }
                c3197e.getRefreshButton().setVisibility(0);
            }
        }

        @Override // android.webkit.WebViewClient
        public void onPageStarted(WebView webView, String str, Bitmap bitmap) {
            C3196d c3196d = (C3196d) C3197e.this.f8705l;
            synchronized (c3196d) {
                C1353c.m367h(c3196d.f8688j, "biz", "h5ld", SystemClock.elapsedRealtime() + "|" + C1383h.m451o(str));
            }
            super.onPageFinished(webView, str);
        }

        @Override // android.webkit.WebViewClient
        public void onReceivedError(WebView webView, int i2, String str, String str2) {
            C3197e c3197e = C3197e.this;
            C3196d c3196d = (C3196d) c3197e.f8705l;
            synchronized (c3196d) {
                c3196d.f8689k = true;
                C1353c.m362c(c3196d.f8688j, "net", "SSLError", "onReceivedError:" + str2);
                c3197e.getRefreshButton().setVisibility(0);
            }
            super.onReceivedError(webView, i2, str, str2);
        }

        @Override // android.webkit.WebViewClient
        public void onReceivedSslError(WebView webView, SslErrorHandler sslErrorHandler, SslError sslError) {
            C3196d c3196d = (C3196d) C3197e.this.f8705l;
            synchronized (c3196d) {
                Activity activity = c3196d.f8683e;
                if (activity == null) {
                    return;
                }
                C1353c.m362c(c3196d.f8688j, "net", "SSLError", "2-" + sslError);
                activity.runOnUiThread(new RunnableC1388e(c3196d, activity, sslErrorHandler));
            }
        }

        @Override // android.webkit.WebViewClient
        public boolean shouldOverrideUrlLoading(WebView webView, String str) {
            boolean z;
            C3196d c3196d = (C3196d) C3197e.this.f8705l;
            synchronized (c3196d) {
                z = false;
                if (!TextUtils.isEmpty(str)) {
                    Activity activity = c3196d.f8683e;
                    if (activity != null) {
                        if (!C1383h.m443g(c3196d.f8688j, str, activity)) {
                            if (str.startsWith("alipayjsbridge://")) {
                                c3196d.m3851g(str.substring(17));
                            } else if (TextUtils.equals(str, "sdklite://h5quit")) {
                                c3196d.m3850f(false);
                            } else if (str.startsWith("http://") || str.startsWith("https://")) {
                                C3197e c3197e = c3196d.f8690l;
                                c3197e.f8702i.loadUrl(str);
                                WebView webView2 = c3197e.f8702i;
                                if (webView2 != null) {
                                    try {
                                        webView2.resumeTimers();
                                    } catch (Throwable unused) {
                                    }
                                }
                            } else {
                                try {
                                    Intent intent = new Intent();
                                    intent.setAction("android.intent.action.VIEW");
                                    intent.setData(Uri.parse(str));
                                    activity.startActivity(intent);
                                } catch (Throwable th) {
                                    C1353c.m365f(c3196d.f8688j, "biz", th);
                                }
                            }
                        }
                    }
                    z = true;
                }
            }
            if (z) {
                return true;
            }
            return super.shouldOverrideUrlLoading(webView, str);
        }
    }

    /* renamed from: com.alipay.sdk.widget.e$d */
    public static final class d {

        /* renamed from: a */
        public boolean f8713a;

        /* renamed from: b */
        public boolean f8714b;

        public d(boolean z, boolean z2) {
            this.f8713a = z;
            this.f8714b = z2;
        }
    }

    /* renamed from: com.alipay.sdk.widget.e$e */
    public interface e {
    }

    /* renamed from: com.alipay.sdk.widget.e$f */
    public interface f {
    }

    /* renamed from: com.alipay.sdk.widget.e$g */
    public interface g {
    }

    public C3197e(Context context, C1373a c1373a, d dVar) {
        super(context, null);
        this.f8707n = new a();
        this.f8703j = dVar;
        this.f8708o = context.getResources().getDisplayMetrics().density;
        setOrientation(1);
        LinearLayout linearLayout = new LinearLayout(context);
        linearLayout.setBackgroundColor(-218103809);
        linearLayout.setOrientation(0);
        linearLayout.setGravity(16);
        linearLayout.setVisibility(dVar.f8713a ? 0 : 8);
        ImageView imageView = new ImageView(context);
        this.f8698e = imageView;
        imageView.setOnClickListener(this.f8707n);
        this.f8698e.setScaleType(ImageView.ScaleType.CENTER);
        this.f8698e.setImageDrawable(C4195m.m4796b("iVBORw0KGgoAAAANSUhEUgAAAEgAAABIBAMAAACnw650AAAAFVBMVEUAAAARjusRkOkQjuoRkeoRj+oQjunya570AAAABnRSTlMAinWeSkk7CjRNAAAAZElEQVRIx+3MOw6AIBQF0YsrMDGx1obaLeGH/S9BQgkJ82rypp4ceTN1ilvyKizmZIAyU7FML0JVYig55BBAfQ2EU4V4CpZJ+2AiSj11C6rUoTannBpRn4W6xNQjLBSI2+TN0w/+3HT2wPClrQAAAABJRU5ErkJggg==", context));
        this.f8698e.setPadding(m3856a(12), 0, m3856a(12), 0);
        linearLayout.addView(this.f8698e, new LinearLayout.LayoutParams(-2, -2));
        View view = new View(context);
        view.setBackgroundColor(-2500135);
        linearLayout.addView(view, new LinearLayout.LayoutParams(m3856a(1), m3856a(25)));
        TextView textView = new TextView(context);
        this.f8699f = textView;
        textView.setTextColor(-15658735);
        this.f8699f.setTextSize(17.0f);
        this.f8699f.setMaxLines(1);
        this.f8699f.setEllipsize(TextUtils.TruncateAt.END);
        LinearLayout.LayoutParams layoutParams = new LinearLayout.LayoutParams(-1, -2);
        layoutParams.setMargins(m3856a(17), 0, 0, 0);
        layoutParams.weight = 1.0f;
        linearLayout.addView(this.f8699f, layoutParams);
        ImageView imageView2 = new ImageView(context);
        this.f8700g = imageView2;
        imageView2.setOnClickListener(this.f8707n);
        this.f8700g.setScaleType(ImageView.ScaleType.CENTER);
        this.f8700g.setImageDrawable(C4195m.m4796b("iVBORw0KGgoAAAANSUhEUgAAAEgAAABICAMAAABiM0N1AAAAmVBMVEUAAAARj+oQjuoRkOsVk/AQj+oRjuoQj+oSkO3///8Rj+kRj+oQkOsTk+whm/8Qj+oRj+oQj+oSkus2p/8QjuoQj+oQj+oQj+oQj+oRj+oTkuwRj+oQj+oRj+oRj+oSkOsSkO0ZlfMbk+8XnPgQj+oRj+oQj+oQj+sSj+sRkOoSkescqv8Rj+oQj+oSj+sXku4Rj+kQjuoQjumXGBCVAAAAMnRSTlMAxPtPF8ry7CoB9npbGwe6lm0wBODazb1+aSejm5GEYjcTDwvls6uJc0g/CdWfRCF20AXrk5QAAAJqSURBVFjD7ZfXmpswEIUFphmDCxi3talurGvm/R8uYSDe5FNBwlzsxf6XmvFBmiaZ/PCdWDk9CWn61OhHCMAaXfoRAth7wx6EkMXnWyrho4yg4bDpquI8Jy78Q7eoj9cmUFijsaLM0JsD9CD0uQAa9aNdPuCFvbA7B9t/Becap8Pu6Q/2jcyH81VHc/WCHDQZXwbvtUhQ61iDlqadncU6Rp31yGkZIzOAu7AjtPpYGREzq/pY5DRFHS1siyO6HfkOKTrMjdb2qevV4zosK7MbkFY2LmYk55hL6juCIFWMOI2KGzblmho3b18EIbxL1hs6r5m2Q2WaEElwS3NW4xh6ZZJuzTtUsBKT4G0h35s4y1mNgkNoS6TZ8SKBXTZQGBNYdPTozXGYKoyLAmOasttjThT4xT6Ch+2qIjRhV9Ja3NC87Kyo5We1vCNEMW1T+j1VLZ9UhE54Q1DL52r5piJ0YxdegvWlHOwTu76uKkJX+MOTHno4YFSEbHYdhViojsLrCTg/MKnhKWaEYzvkZFM8aOkPH7iTSvoFZKD7jGEJbarkRaxQyOeWvGVIbsji152jK7TbDgRzcIuz7SGj89BFU8d30TqWeDtrILxyTkD1IXfvmHseuU3lVHDz607bw0f3xDqejm5ncd0j8VDwfoibRy8RcgTkWHBvocbDbMlJsQAkGnAOHwGy90kLmQY1Wkob07/GaCNRIzdoWK7/+6y/XkLDJCcynOGFuUrKIMuCMonNr9VpSOQoIxBgJ0SacGbzZNy4ICrkscvU2fpElYz+U3sd+aQThjfVmjNa5i15kLcojM3Gz8kP34jf4VaV3X55gNEAAAAASUVORK5CYII=", context));
        this.f8700g.setPadding(m3856a(12), 0, m3856a(12), 0);
        linearLayout.addView(this.f8700g, new LinearLayout.LayoutParams(-2, -2));
        addView(linearLayout, new LinearLayout.LayoutParams(-1, m3856a(48)));
        ProgressBar progressBar = new ProgressBar(context, null, R.style.Widget.ProgressBar.Horizontal);
        this.f8701h = progressBar;
        progressBar.setProgressDrawable(context.getResources().getDrawable(R.drawable.progress_horizontal));
        this.f8701h.setMax(100);
        this.f8701h.setBackgroundColor(-218103809);
        addView(this.f8701h, new LinearLayout.LayoutParams(-1, m3856a(2)));
        WebView webView = new WebView(context);
        this.f8702i = webView;
        webView.setVerticalScrollbarOverlay(true);
        WebView webView2 = this.f8702i;
        String userAgentString = webView2.getSettings().getUserAgentString();
        WebSettings settings = webView2.getSettings();
        StringBuilder m586H = C1499a.m586H(userAgentString);
        StringBuilder m586H2 = C1499a.m586H("Android ");
        m586H2.append(Build.VERSION.RELEASE);
        String sb = m586H2.toString();
        String m448l = C1383h.m448l();
        String locale = context.getResources().getConfiguration().locale.toString();
        String m450n = C1383h.m450n(context);
        StringBuilder sb2 = new StringBuilder();
        sb2.append(" (");
        sb2.append(sb);
        sb2.append(";");
        sb2.append(m448l);
        sb2.append(";");
        C1499a.m608b0(sb2, locale, ";", ";", m450n);
        sb2.append(ChineseToPinyinResource.Field.RIGHT_BRACKET);
        sb2.append("(sdk android)");
        m586H.append(sb2.toString());
        settings.setUserAgentString(m586H.toString());
        WebSettings settings2 = this.f8702i.getSettings();
        settings2.setRenderPriority(WebSettings.RenderPriority.HIGH);
        settings2.setSupportMultipleWindows(true);
        settings2.setUseWideViewPort(true);
        settings2.setAppCacheMaxSize(5242880L);
        settings2.setAppCachePath(context.getCacheDir().getAbsolutePath());
        settings2.setAllowFileAccess(false);
        settings2.setTextSize(WebSettings.TextSize.NORMAL);
        settings2.setAllowFileAccessFromFileURLs(false);
        settings2.setAllowUniversalAccessFromFileURLs(false);
        settings2.setAppCacheEnabled(true);
        settings2.setJavaScriptEnabled(true);
        settings2.setSavePassword(false);
        settings2.setJavaScriptCanOpenWindowsAutomatically(true);
        settings2.setCacheMode(1);
        settings2.setDomStorageEnabled(true);
        settings2.setAllowContentAccess(false);
        this.f8702i.setVerticalScrollbarOverlay(true);
        this.f8702i.setDownloadListener(new C1389f(this, context));
        try {
            try {
                this.f8702i.removeJavascriptInterface("searchBoxJavaBridge_");
                this.f8702i.removeJavascriptInterface("accessibility");
                this.f8702i.removeJavascriptInterface("accessibilityTraversal");
            } catch (Exception unused) {
                Method method = this.f8702i.getClass().getMethod("removeJavascriptInterface", new Class[0]);
                if (method != null) {
                    method.invoke(this.f8702i, "searchBoxJavaBridge_");
                    method.invoke(this.f8702i, "accessibility");
                    method.invoke(this.f8702i, "accessibilityTraversal");
                }
            }
        } catch (Throwable unused2) {
        }
        WebView webView3 = this.f8702i;
        int i2 = AbstractC3195c.f8682c;
        if (webView3 != null) {
            try {
                webView3.resumeTimers();
            } catch (Throwable unused3) {
            }
        }
        addView(this.f8702i, new LinearLayout.LayoutParams(-1, -1));
    }

    /* renamed from: a */
    public final int m3856a(int i2) {
        return (int) (i2 * this.f8708o);
    }

    /* renamed from: b */
    public void m3857b() {
        removeAllViews();
        this.f8702i.removeAllViews();
        this.f8702i.setWebViewClient(null);
        this.f8702i.setWebChromeClient(null);
        this.f8702i.destroy();
    }

    /* renamed from: c */
    public void m3858c(String str) {
        this.f8702i.loadUrl(str);
        WebView webView = this.f8702i;
        int i2 = AbstractC3195c.f8682c;
        if (webView != null) {
            try {
                webView.resumeTimers();
            } catch (Throwable unused) {
            }
        }
    }

    public ImageView getBackButton() {
        return this.f8698e;
    }

    public ProgressBar getProgressbar() {
        return this.f8701h;
    }

    public ImageView getRefreshButton() {
        return this.f8700g;
    }

    public TextView getTitle() {
        return this.f8699f;
    }

    public String getUrl() {
        return this.f8702i.getUrl();
    }

    public WebView getWebView() {
        return this.f8702i;
    }

    public void setChromeProxy(e eVar) {
        this.f8704k = eVar;
        if (eVar == null) {
            this.f8702i.setWebChromeClient(null);
        } else {
            this.f8702i.setWebChromeClient(new b());
        }
    }

    public void setWebClientProxy(f fVar) {
        this.f8705l = fVar;
        if (fVar == null) {
            this.f8702i.setWebViewClient(null);
        } else {
            this.f8702i.setWebViewClient(new c());
        }
    }

    public void setWebEventProxy(g gVar) {
        this.f8706m = gVar;
    }
}
