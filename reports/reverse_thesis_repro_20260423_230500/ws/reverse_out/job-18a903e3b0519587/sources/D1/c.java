package D1;

import B2.B;
import B2.C0166d;
import B2.t;
import B2.z;
import E0.b;
import android.net.Uri;
import android.os.SystemClock;
import com.facebook.imagepipeline.producers.X;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.ReadableMapKeySetIterator;
import com.facebook.react.modules.network.h;
import h2.C0562h;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class c extends E0.b {

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final z f602e;

    public /* synthetic */ class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public static final /* synthetic */ int[] f603a;

        static {
            int[] iArr = new int[D1.a.values().length];
            try {
                iArr[D1.a.f594c.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                iArr[D1.a.f595d.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                iArr[D1.a.f596e.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                iArr[D1.a.f593b.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
            f603a = iArr;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(z zVar) {
        super(zVar);
        j.f(zVar, "okHttpClient");
        this.f602e = zVar;
    }

    private final Map p(ReadableMap readableMap) {
        if (readableMap == null) {
            return null;
        }
        ReadableMapKeySetIterator readableMapKeySetIteratorKeySetIterator = readableMap.keySetIterator();
        HashMap map = new HashMap();
        while (readableMapKeySetIteratorKeySetIterator.hasNextKey()) {
            String strNextKey = readableMapKeySetIteratorKeySetIterator.nextKey();
            String string = readableMap.getString(strNextKey);
            if (string != null) {
                map.put(strNextKey, string);
            }
        }
        return map;
    }

    @Override // E0.b, com.facebook.imagepipeline.producers.X
    /* JADX INFO: renamed from: j */
    public void b(b.C0013b c0013b, X.a aVar) {
        Map mapP;
        j.f(c0013b, "fetchState");
        j.f(aVar, "callback");
        c0013b.f621f = SystemClock.elapsedRealtime();
        Uri uriG = c0013b.g();
        j.e(uriG, "getUri(...)");
        C0166d.a aVar2 = new C0166d.a();
        if (c0013b.b().W() instanceof b) {
            T0.b bVarW = c0013b.b().W();
            j.d(bVarW, "null cannot be cast to non-null type com.facebook.react.modules.fresco.ReactNetworkImageRequest");
            b bVar = (b) bVarW;
            mapP = p(bVar.C());
            int i3 = a.f603a[bVar.B().ordinal()];
            if (i3 == 1) {
                aVar2.e().d();
            } else if (i3 == 2) {
                aVar2.c(Integer.MAX_VALUE, TimeUnit.SECONDS);
            } else if (i3 == 3) {
                aVar2.f().c(Integer.MAX_VALUE, TimeUnit.SECONDS);
            } else {
                if (i3 != 4) {
                    throw new C0562h();
                }
                aVar2.e();
            }
        } else {
            aVar2.e();
            mapP = null;
        }
        t tVarB = h.b(mapP);
        B.a aVar3 = new B.a();
        j.c(tVarB);
        B.a aVarC = aVar3.f(tVarB).c(aVar2.a());
        String string = uriG.toString();
        j.e(string, "toString(...)");
        k(c0013b, aVar, aVarC.m(string).d().b());
    }
}
