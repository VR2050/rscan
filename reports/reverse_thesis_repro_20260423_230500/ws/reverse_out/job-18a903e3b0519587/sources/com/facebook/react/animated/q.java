package com.facebook.react.animated;

import android.view.View;
import com.facebook.react.bridge.JSApplicationIllegalArgumentException;
import com.facebook.react.bridge.JavaOnlyMap;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.ReadableMapKeySetIterator;
import com.facebook.react.bridge.UIManager;
import h2.AbstractC0564j;
import h2.AbstractC0565k;
import java.util.LinkedHashMap;
import java.util.Map;

/* JADX INFO: loaded from: classes.dex */
public final class q extends b {

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final o f6580f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private int f6581g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final Map f6582h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final JavaOnlyMap f6583i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private UIManager f6584j;

    public q(ReadableMap readableMap, o oVar) {
        t2.j.f(readableMap, "config");
        t2.j.f(oVar, "nativeAnimatedNodesManager");
        this.f6580f = oVar;
        this.f6581g = -1;
        this.f6583i = new JavaOnlyMap();
        ReadableMap map = readableMap.getMap("props");
        ReadableMapKeySetIterator readableMapKeySetIteratorKeySetIterator = map != null ? map.keySetIterator() : null;
        this.f6582h = new LinkedHashMap();
        while (readableMapKeySetIteratorKeySetIterator != null && readableMapKeySetIteratorKeySetIterator.hasNextKey()) {
            String strNextKey = readableMapKeySetIteratorKeySetIterator.nextKey();
            this.f6582h.put(strNextKey, Integer.valueOf(map.getInt(strNextKey)));
        }
    }

    @Override // com.facebook.react.animated.b
    public String e() {
        return "PropsAnimatedNode[" + this.f6507d + "] connectedViewTag: " + this.f6581g + " propNodeMapping: " + this.f6582h + " propMap: " + this.f6583i;
    }

    public final void i(int i3, UIManager uIManager) {
        if (this.f6581g == -1) {
            this.f6581g = i3;
            this.f6584j = uIManager;
            return;
        }
        throw new JSApplicationIllegalArgumentException("Animated node " + this.f6507d + " is already attached to a view: " + this.f6581g);
    }

    public final void j(int i3) {
        int i4 = this.f6581g;
        if (i4 == i3 || i4 == -1) {
            this.f6581g = -1;
            return;
        }
        throw new JSApplicationIllegalArgumentException("Attempting to disconnect view that has not been connected with the given animated node: " + i3 + " but is connected to view " + this.f6581g);
    }

    public final View k() {
        Object objA;
        try {
            AbstractC0564j.a aVar = AbstractC0564j.f9276b;
            UIManager uIManager = this.f6584j;
            objA = AbstractC0564j.a(uIManager != null ? uIManager.resolveView(this.f6581g) : null);
        } catch (Throwable th) {
            AbstractC0564j.a aVar2 = AbstractC0564j.f9276b;
            objA = AbstractC0564j.a(AbstractC0565k.a(th));
        }
        return (View) (AbstractC0564j.b(objA) ? null : objA);
    }

    public final void l() {
        int i3 = this.f6581g;
        if (i3 == -1 || L1.a.a(i3) == 2) {
            return;
        }
        ReadableMapKeySetIterator readableMapKeySetIteratorKeySetIterator = this.f6583i.keySetIterator();
        while (readableMapKeySetIteratorKeySetIterator.hasNextKey()) {
            this.f6583i.putNull(readableMapKeySetIteratorKeySetIterator.nextKey());
        }
        UIManager uIManager = this.f6584j;
        if (uIManager != null) {
            uIManager.synchronouslyUpdateViewOnUIThread(this.f6581g, this.f6583i);
        }
    }

    public final void m() {
        if (this.f6581g == -1) {
            return;
        }
        for (Map.Entry entry : this.f6582h.entrySet()) {
            String str = (String) entry.getKey();
            b bVarL = this.f6580f.l(((Number) entry.getValue()).intValue());
            if (bVarL == null) {
                throw new IllegalArgumentException("Mapped property node does not exist");
            }
            if (bVarL instanceof s) {
                ((s) bVarL).i(this.f6583i);
            } else if (bVarL instanceof w) {
                w wVar = (w) bVarL;
                Object objK = wVar.k();
                if (objK instanceof Integer) {
                    this.f6583i.putInt(str, ((Number) objK).intValue());
                } else if (objK instanceof String) {
                    this.f6583i.putString(str, (String) objK);
                } else {
                    this.f6583i.putDouble(str, wVar.l());
                }
            } else if (bVarL instanceof f) {
                this.f6583i.putInt(str, ((f) bVarL).i());
            } else {
                if (!(bVarL instanceof p)) {
                    throw new IllegalArgumentException("Unsupported type of node used in property node " + bVarL.getClass());
                }
                ((p) bVarL).i(str, this.f6583i);
            }
        }
        UIManager uIManager = this.f6584j;
        if (uIManager != null) {
            uIManager.synchronouslyUpdateViewOnUIThread(this.f6581g, this.f6583i);
        }
    }
}
