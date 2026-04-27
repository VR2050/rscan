package com.th3rdwave.safeareacontext;

import android.content.Context;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.uimanager.H0;
import com.facebook.react.uimanager.events.EventDispatcher;

/* JADX INFO: loaded from: classes.dex */
public abstract class g {
    /* JADX INFO: Access modifiers changed from: private */
    public static final void b(f fVar, a aVar, c cVar) {
        Context context = fVar.getContext();
        t2.j.d(context, "null cannot be cast to non-null type com.facebook.react.bridge.ReactContext");
        ReactContext reactContext = (ReactContext) context;
        int id = fVar.getId();
        EventDispatcher eventDispatcherC = H0.c(reactContext, id);
        if (eventDispatcherC != null) {
            eventDispatcherC.g(new b(r.b(reactContext), id, aVar, cVar));
        }
    }
}
