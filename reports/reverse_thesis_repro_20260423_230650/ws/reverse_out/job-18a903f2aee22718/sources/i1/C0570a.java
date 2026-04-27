package i1;

import B2.B;
import B2.D;
import B2.E;
import B2.InterfaceC0167e;
import B2.InterfaceC0168f;
import B2.t;
import B2.z;
import com.facebook.react.devsupport.inspector.InspectorNetworkRequestListener;
import h2.r;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.concurrent.TimeUnit;
import q2.AbstractC0663a;
import t2.j;
import z2.d;

/* JADX INFO: renamed from: i1.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0570a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final C0570a f9328a = new C0570a();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static z f9329b;

    /* JADX INFO: renamed from: i1.a$a, reason: collision with other inner class name */
    public static final class C0132a implements InterfaceC0168f {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ InspectorNetworkRequestListener f9330a;

        C0132a(InspectorNetworkRequestListener inspectorNetworkRequestListener) {
            this.f9330a = inspectorNetworkRequestListener;
        }

        @Override // B2.InterfaceC0168f
        public void a(InterfaceC0167e interfaceC0167e, D d3) {
            InputStream inputStreamB;
            byte[] bArr;
            j.f(interfaceC0167e, "call");
            j.f(d3, "response");
            t tVarP = d3.p();
            HashMap map = new HashMap();
            for (String str : tVarP.c()) {
                map.put(str, tVarP.a(str));
            }
            this.f9330a.onHeaders(d3.i(), map);
            try {
                E eB = d3.b();
                InspectorNetworkRequestListener inspectorNetworkRequestListener = this.f9330a;
                if (eB != null) {
                    try {
                        inputStreamB = eB.b();
                        bArr = new byte[1024];
                    } finally {
                    }
                    while (true) {
                        try {
                            int i3 = inputStreamB.read(bArr);
                            if (i3 == -1) {
                                break;
                            } else {
                                inspectorNetworkRequestListener.onData(new String(bArr, 0, i3, d.f10544b));
                            }
                        } finally {
                        }
                    }
                    r rVar = r.f9288a;
                    AbstractC0663a.a(inputStreamB, null);
                }
                inspectorNetworkRequestListener.onCompletion();
                r rVar2 = r.f9288a;
                AbstractC0663a.a(eB, null);
            } catch (IOException e3) {
                this.f9330a.onError(e3.getMessage());
            }
        }

        @Override // B2.InterfaceC0168f
        public void b(InterfaceC0167e interfaceC0167e, IOException iOException) {
            j.f(interfaceC0167e, "call");
            j.f(iOException, "e");
            if (interfaceC0167e.r()) {
                return;
            }
            this.f9330a.onError(iOException.getMessage());
        }
    }

    private C0570a() {
    }

    public static final void a(String str, InspectorNetworkRequestListener inspectorNetworkRequestListener) {
        j.f(str, "url");
        j.f(inspectorNetworkRequestListener, "listener");
        if (f9329b == null) {
            z.a aVar = new z.a();
            TimeUnit timeUnit = TimeUnit.SECONDS;
            f9329b = aVar.f(10L, timeUnit).W(10L, timeUnit).S(0L, TimeUnit.MINUTES).c();
        }
        try {
            B b3 = new B.a().m(str).b();
            z zVar = f9329b;
            if (zVar == null) {
                j.s("client");
                zVar = null;
            }
            zVar.a(b3).p(new C0132a(inspectorNetworkRequestListener));
        } catch (IllegalArgumentException unused) {
            inspectorNetworkRequestListener.onError("Not a valid URL: " + str);
        }
    }
}
