package com.facebook.react.devsupport;

import B2.B;
import B2.InterfaceC0167e;
import B2.InterfaceC0168f;
import java.io.IOException;
import java.util.Arrays;
import java.util.Locale;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class W {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static final a f6789b = new a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final B2.z f6790a;

    private static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final String b(String str) {
            t2.w wVar = t2.w.f10219a;
            String str2 = String.format(Locale.US, "http://%s/status", Arrays.copyOf(new Object[]{str}, 1));
            t2.j.e(str2, "format(...)");
            return str2;
        }

        private a() {
        }
    }

    public static final class b implements InterfaceC0168f {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ j1.g f6791a;

        b(j1.g gVar) {
            this.f6791a = gVar;
        }

        @Override // B2.InterfaceC0168f
        public void a(InterfaceC0167e interfaceC0167e, B2.D d3) throws IOException {
            t2.j.f(interfaceC0167e, "call");
            t2.j.f(d3, "response");
            if (!d3.f0()) {
                Y.a.m("ReactNative", "Got non-success http code from packager when requesting status: " + d3.i());
                this.f6791a.a(false);
                return;
            }
            B2.E eB = d3.b();
            if (eB == null) {
                Y.a.m("ReactNative", "Got null body response from packager when requesting status");
                this.f6791a.a(false);
                return;
            }
            String strA = eB.A();
            if (t2.j.b("packager-status:running", strA)) {
                this.f6791a.a(true);
                return;
            }
            Y.a.m("ReactNative", "Got unexpected response from packager when requesting status: " + strA);
            this.f6791a.a(false);
        }

        @Override // B2.InterfaceC0168f
        public void b(InterfaceC0167e interfaceC0167e, IOException iOException) {
            t2.j.f(interfaceC0167e, "call");
            t2.j.f(iOException, "e");
            Y.a.I("ReactNative", "The packager does not seem to be running as we got an IOException requesting its status: " + iOException.getMessage());
            this.f6791a.a(false);
        }
    }

    public W(B2.z zVar) {
        t2.j.f(zVar, "client");
        this.f6790a = zVar;
    }

    public final void a(String str, j1.g gVar) {
        t2.j.f(str, "host");
        t2.j.f(gVar, "callback");
        this.f6790a.a(new B.a().m(f6789b.b(str)).b()).p(new b(gVar));
    }
}
