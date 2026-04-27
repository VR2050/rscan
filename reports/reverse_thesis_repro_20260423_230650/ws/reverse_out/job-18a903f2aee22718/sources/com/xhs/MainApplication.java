package com.xhs;

import android.app.Application;
import android.content.Context;
import c1.C0337i;
import c1.InterfaceC0349v;
import c1.InterfaceC0351x;
import c1.K;
import com.facebook.react.defaults.d;
import com.facebook.react.defaults.f;
import com.facebook.react.soloader.OpenSourceMergedSoMapping;
import com.facebook.soloader.SoLoader;
import java.util.ArrayList;
import java.util.List;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class MainApplication extends Application implements InterfaceC0349v {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final K f8777b = new a(this);

    public static final class a extends f {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final boolean f8778c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final boolean f8779d;

        a(MainApplication mainApplication) {
            super(mainApplication);
            this.f8778c = true;
            this.f8779d = true;
        }

        @Override // c1.K
        protected String j() {
            return "index";
        }

        @Override // c1.K
        protected List m() {
            ArrayList arrayListA = new C0337i(this).a();
            j.e(arrayListA, "apply(...)");
            return arrayListA;
        }

        @Override // c1.K
        public boolean u() {
            return false;
        }

        @Override // com.facebook.react.defaults.f
        protected Boolean y() {
            return Boolean.valueOf(this.f8779d);
        }

        @Override // com.facebook.react.defaults.f
        protected boolean z() {
            return this.f8778c;
        }
    }

    @Override // c1.InterfaceC0349v
    public K a() {
        return this.f8777b;
    }

    @Override // c1.InterfaceC0349v
    public InterfaceC0351x b() {
        Context applicationContext = getApplicationContext();
        j.e(applicationContext, "getApplicationContext(...)");
        return d.e(applicationContext, a(), null, 4, null);
    }

    @Override // android.app.Application
    public void onCreate() {
        super.onCreate();
        SoLoader.l(this, OpenSourceMergedSoMapping.f7354a);
        com.facebook.react.defaults.a.d(false, false, false, 7, null);
    }
}
