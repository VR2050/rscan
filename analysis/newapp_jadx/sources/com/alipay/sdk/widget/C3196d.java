package com.alipay.sdk.widget;

import android.app.Activity;
import android.text.TextUtils;
import android.view.MotionEvent;
import android.view.animation.Animation;
import android.view.animation.TranslateAnimation;
import android.webkit.WebView;
import android.widget.ImageView;
import com.alipay.sdk.widget.C3197e;
import com.jbzd.media.movecartoons.bean.response.FindBean;
import com.jbzd.media.movecartoons.p396ui.index.home.child.VideoListActivity;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import org.json.JSONObject;
import p005b.p085c.p088b.p089a.C1349f;
import p005b.p085c.p088b.p089a.EnumC1350g;
import p005b.p085c.p088b.p089a.p090h.C1353c;
import p005b.p085c.p088b.p098h.C1373a;
import p005b.p085c.p088b.p100j.C1383h;
import p005b.p085c.p088b.p101k.C1390g;
import p005b.p085c.p088b.p101k.RunnableC1387d;

/* renamed from: com.alipay.sdk.widget.d */
/* loaded from: classes.dex */
public class C3196d extends AbstractC3195c implements C3197e.e, C3197e.f, C3197e.g {

    /* renamed from: g */
    public boolean f8685g;

    /* renamed from: h */
    public String f8686h;

    /* renamed from: i */
    public boolean f8687i;

    /* renamed from: j */
    public final C1373a f8688j;

    /* renamed from: k */
    public boolean f8689k;

    /* renamed from: l */
    public C3197e f8690l;

    /* renamed from: m */
    public C1390g f8691m;

    /* renamed from: com.alipay.sdk.widget.d$a */
    public class a extends c {

        /* renamed from: a */
        public final /* synthetic */ C3197e f8692a;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public a(C3197e c3197e) {
            super(C3196d.this, null);
            this.f8692a = c3197e;
        }

        @Override // android.view.animation.Animation.AnimationListener
        public void onAnimationEnd(Animation animation) {
            this.f8692a.m3857b();
            C3196d.this.f8687i = false;
        }
    }

    /* renamed from: com.alipay.sdk.widget.d$b */
    public class b extends c {

        /* renamed from: a */
        public final /* synthetic */ C3197e f8694a;

        /* renamed from: b */
        public final /* synthetic */ String f8695b;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public b(C3197e c3197e, String str) {
            super(C3196d.this, null);
            this.f8694a = c3197e;
            this.f8695b = str;
        }

        @Override // android.view.animation.Animation.AnimationListener
        public void onAnimationEnd(Animation animation) {
            C3196d.this.removeView(this.f8694a);
            C3196d.this.f8690l.m3858c(this.f8695b);
            C3196d.this.f8687i = false;
        }
    }

    /* renamed from: com.alipay.sdk.widget.d$c */
    public abstract class c implements Animation.AnimationListener {
        public c(C3196d c3196d, RunnableC1387d runnableC1387d) {
        }

        @Override // android.view.animation.Animation.AnimationListener
        public void onAnimationRepeat(Animation animation) {
        }

        @Override // android.view.animation.Animation.AnimationListener
        public void onAnimationStart(Animation animation) {
        }
    }

    public C3196d(Activity activity, C1373a c1373a, String str) {
        super(activity, str);
        boolean z = true;
        this.f8685g = true;
        this.f8686h = "GET";
        this.f8687i = false;
        this.f8690l = null;
        this.f8691m = new C1390g();
        this.f8688j = c1373a;
        synchronized (this) {
            try {
                boolean z2 = !m3847c();
                if (m3847c()) {
                    z = false;
                }
                C3197e c3197e = new C3197e(this.f8683e, c1373a, new C3197e.d(z2, z));
                this.f8690l = c3197e;
                c3197e.setChromeProxy(this);
                this.f8690l.setWebClientProxy(this);
                this.f8690l.setWebEventProxy(this);
                addView(this.f8690l);
            } catch (Exception unused) {
            }
        }
    }

    @Override // com.alipay.sdk.widget.AbstractC3195c
    /* renamed from: a */
    public synchronized void mo3845a() {
        this.f8690l.m3857b();
        C1390g c1390g = this.f8691m;
        if (!c1390g.m457a()) {
            Iterator<C3197e> it = c1390g.f1322a.iterator();
            while (it.hasNext()) {
                it.next().m3857b();
            }
            c1390g.f1322a.clear();
        }
    }

    @Override // com.alipay.sdk.widget.AbstractC3195c
    /* renamed from: b */
    public synchronized boolean mo3846b() {
        Activity activity = this.f8683e;
        if (activity == null) {
            return true;
        }
        if (!m3847c()) {
            if (!this.f8687i) {
                m3853i();
            }
            return true;
        }
        C3197e c3197e = this.f8690l;
        if (c3197e != null && c3197e.getWebView() != null) {
            if (!c3197e.getWebView().canGoBack()) {
                C1349f.f1170b = C1349f.m357b();
                activity.finish();
            } else if (this.f8689k) {
                EnumC1350g m358a = EnumC1350g.m358a(6002);
                C1349f.f1170b = C1349f.m356a(m358a.f1179l, m358a.f1180m, "");
                activity.finish();
            }
            return true;
        }
        activity.finish();
        return true;
    }

    /* renamed from: d */
    public synchronized void m3848d(String str) {
        if ("POST".equals(this.f8686h)) {
            this.f8690l.f8702i.postUrl(str, null);
        } else {
            C3197e c3197e = this.f8690l;
            c3197e.f8702i.loadUrl(str);
            WebView webView = c3197e.f8702i;
            if (webView != null) {
                try {
                    webView.resumeTimers();
                } catch (Throwable unused) {
                }
            }
        }
        WebView webView2 = this.f8690l.getWebView();
        if (webView2 != null) {
            try {
                webView2.resumeTimers();
            } catch (Throwable unused2) {
            }
        }
    }

    /* renamed from: e */
    public final synchronized void m3849e(String str, String str2, String str3) {
        C3197e c3197e = this.f8690l;
        if (c3197e == null) {
            return;
        }
        JSONObject m449m = C1383h.m449m(str3);
        if (VideoListActivity.KEY_TITLE.equals(str) && m449m.has(VideoListActivity.KEY_TITLE)) {
            c3197e.getTitle().setText(m449m.optString(VideoListActivity.KEY_TITLE, ""));
        } else if ("refresh".equals(str)) {
            c3197e.getWebView().reload();
        } else if ("back".equals(str)) {
            m3854j();
        } else {
            int i2 = 0;
            if ("exit".equals(str)) {
                C1349f.f1170b = m449m.optString("result", null);
                m3850f(m449m.optBoolean(FindBean.status_success, false));
            } else if ("backButton".equals(str)) {
                boolean optBoolean = m449m.optBoolean("show", true);
                ImageView backButton = c3197e.getBackButton();
                if (!optBoolean) {
                    i2 = 4;
                }
                backButton.setVisibility(i2);
            } else if ("refreshButton".equals(str)) {
                boolean optBoolean2 = m449m.optBoolean("show", true);
                ImageView refreshButton = c3197e.getRefreshButton();
                if (!optBoolean2) {
                    i2 = 4;
                }
                refreshButton.setVisibility(i2);
            } else if ("pushWindow".equals(str) && m449m.optString("url", null) != null) {
                m3852h(m449m.optString("url"), m449m.optString(VideoListActivity.KEY_TITLE, ""));
            } else if ("sdkInfo".equals(str)) {
                JSONObject jSONObject = new JSONObject();
                try {
                    jSONObject.put("sdk_version", "15.7.7");
                    jSONObject.put("app_name", this.f8688j.f1248b);
                    jSONObject.put("app_version", this.f8688j.f1247a);
                } catch (Throwable th) {
                    C1353c.m363d(this.f8688j, "biz", "jInfoErr", th);
                }
                c3197e.m3858c(String.format("window.AlipayJSBridge.callBackFromNativeFunc('%s','%s');", str2, jSONObject.toString().replace("'", "")));
            }
        }
    }

    /* renamed from: f */
    public final synchronized void m3850f(boolean z) {
        C1349f.f1169a = z;
        this.f8683e.finish();
    }

    /* renamed from: g */
    public final synchronized void m3851g(String str) {
        Map<String, String> m442f = C1383h.m442f(this.f8688j, str);
        if (str.startsWith("callNativeFunc")) {
            HashMap hashMap = (HashMap) m442f;
            m3849e((String) hashMap.get("func"), (String) hashMap.get("cbId"), (String) ((HashMap) m442f).get("data"));
        } else if (str.startsWith("onBack")) {
            m3854j();
        } else if (str.startsWith("setTitle") && ((HashMap) m442f).containsKey(VideoListActivity.KEY_TITLE)) {
            this.f8690l.getTitle().setText((CharSequence) ((HashMap) m442f).get(VideoListActivity.KEY_TITLE));
        } else if (str.startsWith("onRefresh")) {
            this.f8690l.getWebView().reload();
        } else if (str.startsWith("showBackButton") && ((HashMap) m442f).containsKey("bshow")) {
            this.f8690l.getBackButton().setVisibility(TextUtils.equals("true", (CharSequence) ((HashMap) m442f).get("bshow")) ? 0 : 4);
        } else if (str.startsWith("onExit")) {
            C1349f.f1170b = (String) ((HashMap) m442f).get("result");
            m3850f(TextUtils.equals("true", (CharSequence) ((HashMap) m442f).get("bsucc")));
        } else if (str.startsWith("onLoadJs")) {
            C3197e c3197e = this.f8690l;
            c3197e.f8702i.loadUrl("javascript:(function() {\n    if (window.AlipayJSBridge) {\n        return\n    }\n\n    function alipayjsbridgeFunc(url) {\n        var iframe = document.createElement(\"iframe\");\n        iframe.style.width = \"1px\";\n        iframe.style.height = \"1px\";\n        iframe.style.display = \"none\";\n        iframe.src = url;\n        document.body.appendChild(iframe);\n        setTimeout(function() {\n            document.body.removeChild(iframe)\n        }, 100)\n    }\n    window.alipayjsbridgeSetTitle = function(title) {\n        document.title = title;\n        alipayjsbridgeFunc(\"alipayjsbridge://setTitle?title=\" + encodeURIComponent(title))\n    };\n    window.alipayjsbridgeRefresh = function() {\n        alipayjsbridgeFunc(\"alipayjsbridge://onRefresh?\")\n    };\n    window.alipayjsbridgeBack = function() {\n        alipayjsbridgeFunc(\"alipayjsbridge://onBack?\")\n    };\n    window.alipayjsbridgeExit = function(bsucc) {\n        alipayjsbridgeFunc(\"alipayjsbridge://onExit?bsucc=\" + bsucc)\n    };\n    window.alipayjsbridgeShowBackButton = function(bshow) {\n        alipayjsbridgeFunc(\"alipayjsbridge://showBackButton?bshow=\" + bshow)\n    };\n    window.AlipayJSBridge = {\n        version: \"2.0\",\n        addListener: addListener,\n        hasListener: hasListener,\n        callListener: callListener,\n        callNativeFunc: callNativeFunc,\n        callBackFromNativeFunc: callBackFromNativeFunc\n    };\n    var uniqueId = 1;\n    var h5JsCallbackMap = {};\n\n    function iframeCall(paramStr) {\n        setTimeout(function() {\n        \tvar iframe = document.createElement(\"iframe\");\n        \tiframe.style.width = \"1px\";\n        \tiframe.style.height = \"1px\";\n        \tiframe.style.display = \"none\";\n        \tiframe.src = \"alipayjsbridge://callNativeFunc?\" + paramStr;\n        \tvar parent = document.body || document.documentElement;\n        \tparent.appendChild(iframe);\n        \tsetTimeout(function() {\n            \tparent.removeChild(iframe)\n        \t}, 0)\n        }, 0)\n    }\n\n    function callNativeFunc(nativeFuncName, data, h5JsCallback) {\n        var h5JsCallbackId = \"\";\n        if (h5JsCallback) {\n            h5JsCallbackId = \"cb_\" + (uniqueId++) + \"_\" + new Date().getTime();\n            h5JsCallbackMap[h5JsCallbackId] = h5JsCallback\n        }\n        var dataStr = \"\";\n        if (data) {\n            dataStr = encodeURIComponent(JSON.stringify(data))\n        }\n        var paramStr = \"func=\" + nativeFuncName + \"&cbId=\" + h5JsCallbackId + \"&data=\" + dataStr;\n        iframeCall(paramStr)\n    }\n\n    function callBackFromNativeFunc(h5JsCallbackId, data) {\n        var h5JsCallback = h5JsCallbackMap[h5JsCallbackId];\n        if (h5JsCallback) {\n            h5JsCallback(data);\n            delete h5JsCallbackMap[h5JsCallbackId]\n        }\n    }\n    var h5ListenerMap = {};\n\n    function addListener(jsFuncName, jsFunc) {\n        h5ListenerMap[jsFuncName] = jsFunc\n    }\n\n    function hasListener(jsFuncName) {\n        var jsFunc = h5ListenerMap[jsFuncName];\n        if (!jsFunc) {\n            return false\n        }\n        return true\n    }\n\n    function callListener(h5JsFuncName, data, nativeCallbackId) {\n        var responseCallback;\n        if (nativeCallbackId) {\n            responseCallback = function(responseData) {\n                var dataStr = \"\";\n                if (responseData) {\n                    dataStr = encodeURIComponent(JSON.stringify(responseData))\n                }\n                var paramStr = \"func=h5JsFuncCallback\" + \"&cbId=\" + nativeCallbackId + \"&data=\" + dataStr;\n                iframeCall(paramStr)\n            }\n        }\n        var h5JsFunc = h5ListenerMap[h5JsFuncName];\n        if (h5JsFunc) {\n            h5JsFunc(data, responseCallback)\n        } else if (h5JsFuncName == \"h5BackAction\") {\n            if (!window.alipayjsbridgeH5BackAction || !alipayjsbridgeH5BackAction()) {\n                var paramStr = \"func=back\";\n                iframeCall(paramStr)\n            }\n        } else {\n            console.log(\"AlipayJSBridge: no h5JsFunc \" + h5JsFuncName + data)\n        }\n    }\n    var event;\n    if (window.CustomEvent) {\n        event = new CustomEvent(\"alipayjsbridgeready\")\n    } else {\n        event = document.createEvent(\"Event\");\n        event.initEvent(\"alipayjsbridgeready\", true, true)\n    }\n    document.dispatchEvent(event);\n    setTimeout(excuteH5InitFuncs, 0);\n\n    function excuteH5InitFuncs() {\n        if (window.AlipayJSBridgeInitArray) {\n            var h5InitFuncs = window.AlipayJSBridgeInitArray;\n            delete window.AlipayJSBridgeInitArray;\n            for (var i = 0; i < h5InitFuncs.length; i++) {\n                try {\n                    h5InitFuncs[i](AlipayJSBridge)\n                } catch (e) {\n                    setTimeout(function() {\n                        throw e\n                    })\n                }\n            }\n        }\n    }\n})();\n");
            WebView webView = c3197e.f8702i;
            if (webView != null) {
                try {
                    webView.resumeTimers();
                } catch (Throwable unused) {
                }
            }
        }
    }

    /* renamed from: h */
    public final synchronized boolean m3852h(String str, String str2) {
        C3197e c3197e = this.f8690l;
        try {
            C3197e c3197e2 = new C3197e(this.f8683e, this.f8688j, new C3197e.d(!m3847c(), !m3847c()));
            this.f8690l = c3197e2;
            c3197e2.setChromeProxy(this);
            this.f8690l.setWebClientProxy(this);
            this.f8690l.setWebEventProxy(this);
            if (!TextUtils.isEmpty(str2)) {
                this.f8690l.getTitle().setText(str2);
            }
            this.f8687i = true;
            this.f8691m.f1322a.push(c3197e);
            TranslateAnimation translateAnimation = new TranslateAnimation(1, 1.0f, 1, 0.0f, 1, 0.0f, 1, 0.0f);
            translateAnimation.setDuration(400L);
            translateAnimation.setFillAfter(false);
            translateAnimation.setAnimationListener(new b(c3197e, str));
            this.f8690l.setAnimation(translateAnimation);
            addView(this.f8690l);
        } catch (Throwable unused) {
            return false;
        }
        return true;
    }

    /* renamed from: i */
    public final synchronized void m3853i() {
        Activity activity = this.f8683e;
        C3197e c3197e = this.f8690l;
        if (activity != null && c3197e != null) {
            if (this.f8685g) {
                activity.finish();
            } else {
                c3197e.f8702i.loadUrl("javascript:window.AlipayJSBridge.callListener('h5BackAction');");
                WebView webView = c3197e.f8702i;
                if (webView != null) {
                    try {
                        webView.resumeTimers();
                    } catch (Throwable unused) {
                    }
                }
            }
        }
    }

    /* renamed from: j */
    public final synchronized void m3854j() {
        WebView webView = this.f8690l.getWebView();
        if (webView.canGoBack()) {
            webView.goBack();
        } else {
            C1390g c1390g = this.f8691m;
            if (c1390g == null || c1390g.m457a()) {
                m3850f(false);
            } else {
                m3855k();
            }
        }
    }

    /* renamed from: k */
    public final synchronized boolean m3855k() {
        if (this.f8691m.m457a()) {
            this.f8683e.finish();
        } else {
            this.f8687i = true;
            C3197e c3197e = this.f8690l;
            this.f8690l = this.f8691m.f1322a.pop();
            TranslateAnimation translateAnimation = new TranslateAnimation(1, 0.0f, 1, 1.0f, 1, 0.0f, 1, 0.0f);
            translateAnimation.setDuration(400L);
            translateAnimation.setFillAfter(false);
            translateAnimation.setAnimationListener(new a(c3197e));
            c3197e.setAnimation(translateAnimation);
            removeView(c3197e);
            addView(this.f8690l);
        }
        return true;
    }

    @Override // android.view.ViewGroup
    public synchronized boolean onInterceptTouchEvent(MotionEvent motionEvent) {
        return this.f8687i ? true : super.onInterceptTouchEvent(motionEvent);
    }
}
