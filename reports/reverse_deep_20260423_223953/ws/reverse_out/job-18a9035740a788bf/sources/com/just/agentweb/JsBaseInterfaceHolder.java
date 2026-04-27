package com.just.agentweb;

import android.os.Build;
import android.webkit.JavascriptInterface;
import com.just.agentweb.AgentWeb;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;

/* JADX INFO: loaded from: classes3.dex */
public abstract class JsBaseInterfaceHolder implements JsInterfaceHolder {
    private AgentWeb.SecurityType mSecurityType;
    private WebCreator mWebCreator;

    protected JsBaseInterfaceHolder(WebCreator webCreator, AgentWeb.SecurityType securityType) {
        this.mSecurityType = securityType;
        this.mWebCreator = webCreator;
    }

    @Override // com.just.agentweb.JsInterfaceHolder
    public boolean checkObject(Object v) {
        if (Build.VERSION.SDK_INT < 17 || this.mWebCreator.getWebViewType() == 2) {
            return true;
        }
        boolean tag = false;
        Method[] mMethods = v.getClass().getMethods();
        for (Method mMethod : mMethods) {
            Annotation[] mAnnotations = mMethod.getAnnotations();
            int length = mAnnotations.length;
            int i = 0;
            while (true) {
                if (i >= length) {
                    break;
                }
                Annotation mAnnotation = mAnnotations[i];
                if (!(mAnnotation instanceof JavascriptInterface)) {
                    i++;
                } else {
                    tag = true;
                    break;
                }
            }
            if (tag) {
                break;
            }
        }
        return tag;
    }

    protected boolean checkSecurity() {
        return this.mSecurityType != AgentWeb.SecurityType.STRICT_CHECK || this.mWebCreator.getWebViewType() == 2 || Build.VERSION.SDK_INT > 17;
    }
}
