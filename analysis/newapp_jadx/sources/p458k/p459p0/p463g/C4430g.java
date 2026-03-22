package p458k.p459p0.p463g;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p458k.C4381g0;
import p458k.C4389k0;
import p458k.InterfaceC4369a0;
import p458k.InterfaceC4378f;
import p458k.InterfaceC4388k;
import p458k.p459p0.p462f.C4413c;
import p458k.p459p0.p462f.C4423m;

/* renamed from: k.p0.g.g */
/* loaded from: classes3.dex */
public final class C4430g implements InterfaceC4369a0.a {

    /* renamed from: a */
    public int f11734a;

    /* renamed from: b */
    public final List<InterfaceC4369a0> f11735b;

    /* renamed from: c */
    public final C4423m f11736c;

    /* renamed from: d */
    public final C4413c f11737d;

    /* renamed from: e */
    public final int f11738e;

    /* renamed from: f */
    public final C4381g0 f11739f;

    /* renamed from: g */
    public final InterfaceC4378f f11740g;

    /* renamed from: h */
    public final int f11741h;

    /* renamed from: i */
    public final int f11742i;

    /* renamed from: j */
    public final int f11743j;

    /* JADX WARN: Multi-variable type inference failed */
    public C4430g(@NotNull List<? extends InterfaceC4369a0> interceptors, @NotNull C4423m transmitter, @Nullable C4413c c4413c, int i2, @NotNull C4381g0 request, @NotNull InterfaceC4378f call, int i3, int i4, int i5) {
        Intrinsics.checkParameterIsNotNull(interceptors, "interceptors");
        Intrinsics.checkParameterIsNotNull(transmitter, "transmitter");
        Intrinsics.checkParameterIsNotNull(request, "request");
        Intrinsics.checkParameterIsNotNull(call, "call");
        this.f11735b = interceptors;
        this.f11736c = transmitter;
        this.f11737d = c4413c;
        this.f11738e = i2;
        this.f11739f = request;
        this.f11740g = call;
        this.f11741h = i3;
        this.f11742i = i4;
        this.f11743j = i5;
    }

    @Override // p458k.InterfaceC4369a0.a
    /* renamed from: a */
    public int mo4941a() {
        return this.f11742i;
    }

    @Override // p458k.InterfaceC4369a0.a
    /* renamed from: b */
    public int mo4942b() {
        return this.f11743j;
    }

    @Nullable
    /* renamed from: c */
    public InterfaceC4388k m5138c() {
        C4413c c4413c = this.f11737d;
        if (c4413c != null) {
            return c4413c.m5084b();
        }
        return null;
    }

    @NotNull
    /* renamed from: d */
    public C4389k0 m5139d(@NotNull C4381g0 request) {
        Intrinsics.checkParameterIsNotNull(request, "request");
        return m5140e(request, this.f11736c, this.f11737d);
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x003c  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x010f  */
    @org.jetbrains.annotations.NotNull
    /* renamed from: e */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final p458k.C4389k0 m5140e(@org.jetbrains.annotations.NotNull p458k.C4381g0 r16, @org.jetbrains.annotations.NotNull p458k.p459p0.p462f.C4423m r17, @org.jetbrains.annotations.Nullable p458k.p459p0.p462f.C4413c r18) {
        /*
            Method dump skipped, instructions count: 314
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p458k.p459p0.p463g.C4430g.m5140e(k.g0, k.p0.f.m, k.p0.f.c):k.k0");
    }
}
