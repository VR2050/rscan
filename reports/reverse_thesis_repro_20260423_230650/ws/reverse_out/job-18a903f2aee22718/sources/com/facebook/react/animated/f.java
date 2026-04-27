package com.facebook.react.animated;

import android.app.Activity;
import android.content.Context;
import android.graphics.Color;
import android.view.View;
import com.facebook.react.bridge.ColorPropConverter;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReadableMap;
import java.util.Iterator;
import java.util.List;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class f extends b implements d {

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    public static final a f6512n = new a(null);

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final o f6513f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final ReactApplicationContext f6514g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private int f6515h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private int f6516i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private int f6517j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private int f6518k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private ReadableMap f6519l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private boolean f6520m;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final Context b(b bVar) {
            List list = bVar.f6504a;
            if (list == null) {
                return null;
            }
            Iterator it = list.iterator();
            if (!it.hasNext()) {
                return null;
            }
            b bVar2 = (b) it.next();
            if (!(bVar2 instanceof q)) {
                return f.f6512n.b(bVar2);
            }
            View viewK = ((q) bVar2).k();
            if (viewK != null) {
                return viewK.getContext();
            }
            return null;
        }

        private a() {
        }
    }

    public f(ReadableMap readableMap, o oVar, ReactApplicationContext reactApplicationContext) {
        t2.j.f(readableMap, "config");
        t2.j.f(oVar, "nativeAnimatedNodesManager");
        t2.j.f(reactApplicationContext, "reactApplicationContext");
        this.f6513f = oVar;
        this.f6514g = reactApplicationContext;
        a(readableMap);
    }

    private final Context j() {
        Activity currentActivity = this.f6514g.getCurrentActivity();
        return currentActivity != null ? currentActivity : f6512n.b(this);
    }

    private final void k() {
        Context contextJ;
        if (this.f6519l == null || this.f6520m || (contextJ = j()) == null) {
            return;
        }
        Integer color = ColorPropConverter.getColor(this.f6519l, contextJ);
        w wVar = (w) this.f6513f.l(this.f6515h);
        w wVar2 = (w) this.f6513f.l(this.f6516i);
        w wVar3 = (w) this.f6513f.l(this.f6517j);
        w wVar4 = (w) this.f6513f.l(this.f6518k);
        if (wVar != null) {
            t2.j.c(color);
            wVar.f6621f = Color.red(color.intValue());
        }
        if (wVar2 != null) {
            t2.j.c(color);
            wVar2.f6621f = Color.green(color.intValue());
        }
        if (wVar3 != null) {
            t2.j.c(color);
            wVar3.f6621f = Color.blue(color.intValue());
        }
        if (wVar4 != null) {
            t2.j.c(color);
            wVar4.f6621f = ((double) Color.alpha(color.intValue())) / 255.0d;
        }
        this.f6520m = true;
    }

    @Override // com.facebook.react.animated.d
    public void a(ReadableMap readableMap) {
        if (readableMap == null) {
            this.f6515h = 0;
            this.f6516i = 0;
            this.f6517j = 0;
            this.f6518k = 0;
            this.f6519l = null;
            this.f6520m = false;
            return;
        }
        this.f6515h = readableMap.getInt("r");
        this.f6516i = readableMap.getInt("g");
        this.f6517j = readableMap.getInt("b");
        this.f6518k = readableMap.getInt("a");
        this.f6519l = readableMap.getMap("nativeColor");
        this.f6520m = false;
        k();
    }

    @Override // com.facebook.react.animated.b
    public String e() {
        return "ColorAnimatedNode[" + this.f6507d + "]: r: " + this.f6515h + "  g: " + this.f6516i + " b: " + this.f6517j + " a: " + this.f6518k;
    }

    public final int i() {
        k();
        w wVar = (w) this.f6513f.l(this.f6515h);
        w wVar2 = (w) this.f6513f.l(this.f6516i);
        w wVar3 = (w) this.f6513f.l(this.f6517j);
        w wVar4 = (w) this.f6513f.l(this.f6518k);
        return com.facebook.react.views.view.d.b(wVar != null ? wVar.f6621f : 0.0d, wVar2 != null ? wVar2.f6621f : 0.0d, wVar3 != null ? wVar3.f6621f : 0.0d, wVar4 != null ? wVar4.f6621f : 0.0d);
    }
}
