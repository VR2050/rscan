package com.just.agentweb;

import android.app.Activity;
import android.os.Handler;
import android.os.Message;
import android.webkit.JavascriptInterface;
import java.lang.ref.WeakReference;

/* JADX INFO: loaded from: classes3.dex */
public class AgentWebJsInterfaceCompat {
    private String TAG = getClass().getSimpleName();
    private WeakReference<Activity> mActivityWeakReference;
    private WeakReference<AgentWeb> mReference;

    AgentWebJsInterfaceCompat(AgentWeb agentWeb, Activity activity) {
        this.mReference = null;
        this.mActivityWeakReference = null;
        this.mReference = new WeakReference<>(agentWeb);
        this.mActivityWeakReference = new WeakReference<>(activity);
    }

    @JavascriptInterface
    public void uploadFile() {
        uploadFile("*/*");
    }

    @JavascriptInterface
    public void uploadFile(String acceptType) {
        LogUtils.i(this.TAG, acceptType + "  " + this.mActivityWeakReference.get() + "  " + this.mReference.get());
        if (this.mActivityWeakReference.get() != null && this.mReference.get() != null) {
            AgentWebUtils.showFileChooserCompat(this.mActivityWeakReference.get(), this.mReference.get().getWebCreator().getWebView(), null, null, this.mReference.get().getPermissionInterceptor(), null, acceptType, new Handler.Callback() { // from class: com.just.agentweb.AgentWebJsInterfaceCompat.1
                @Override // android.os.Handler.Callback
                public boolean handleMessage(Message msg) {
                    if (AgentWebJsInterfaceCompat.this.mReference.get() != null) {
                        JsAccessEntrace jsAccessEntrace = ((AgentWeb) AgentWebJsInterfaceCompat.this.mReference.get()).getJsAccessEntrace();
                        String[] strArr = new String[1];
                        strArr[0] = msg.obj instanceof String ? (String) msg.obj : null;
                        jsAccessEntrace.quickCallJs("uploadFileResult", strArr);
                    }
                    return true;
                }
            });
        }
    }
}
