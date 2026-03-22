package com.bumptech.glide;

import android.content.Context;
import android.util.Log;
import androidx.annotation.NonNull;
import com.qunidayede.supportlibrary.imageloader.XAppGlideModule;
import java.util.Collections;
import java.util.Objects;
import java.util.Set;
import p005b.p143g.p144a.C1551a;
import p005b.p143g.p144a.C1554d;
import p005b.p143g.p144a.C1557g;
import p005b.p143g.p144a.ComponentCallbacks2C1553c;
import p005b.p143g.p144a.p163n.C1758l;

/* loaded from: classes.dex */
public final class GeneratedAppGlideModuleImpl extends GeneratedAppGlideModule {

    /* renamed from: a */
    public final XAppGlideModule f8841a = new XAppGlideModule();

    public GeneratedAppGlideModuleImpl(Context context) {
        Log.isLoggable("Glide", 3);
    }

    @Override // p005b.p143g.p144a.p164o.AbstractC1762a, p005b.p143g.p144a.p164o.InterfaceC1763b
    /* renamed from: a */
    public void mo1061a(@NonNull Context context, @NonNull C1554d c1554d) {
        this.f8841a.mo1061a(context, c1554d);
    }

    @Override // p005b.p143g.p144a.p164o.AbstractC1765d, p005b.p143g.p144a.p164o.InterfaceC1767f
    /* renamed from: b */
    public void mo1063b(@NonNull Context context, @NonNull ComponentCallbacks2C1553c componentCallbacks2C1553c, @NonNull C1557g c1557g) {
        this.f8841a.mo1063b(context, componentCallbacks2C1553c, c1557g);
    }

    @Override // p005b.p143g.p144a.p164o.AbstractC1762a
    /* renamed from: c */
    public boolean mo1062c() {
        Objects.requireNonNull(this.f8841a);
        return true;
    }

    @Override // com.bumptech.glide.GeneratedAppGlideModule
    @NonNull
    /* renamed from: d */
    public Set<Class<?>> mo3890d() {
        return Collections.emptySet();
    }

    @Override // com.bumptech.glide.GeneratedAppGlideModule
    @NonNull
    /* renamed from: e */
    public C1758l.b mo3891e() {
        return new C1551a();
    }
}
