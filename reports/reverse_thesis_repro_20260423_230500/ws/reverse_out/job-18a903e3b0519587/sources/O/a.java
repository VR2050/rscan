package O;

import B2.E;
import B2.x;
import Q2.F;
import Q2.G;
import Q2.i;
import Q2.k;
import Q2.t;
import com.RNFetchBlob.f;
import com.RNFetchBlob.g;
import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.modules.core.DeviceEventManagerModule;
import java.nio.charset.Charset;

/* JADX INFO: loaded from: classes.dex */
public class a extends E {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    String f2019c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    ReactApplicationContext f2020d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    E f2021e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    boolean f2022f;

    public a(ReactApplicationContext reactApplicationContext, String str, E e3, boolean z3) {
        this.f2020d = reactApplicationContext;
        this.f2019c = str;
        this.f2021e = e3;
        this.f2022f = z3;
    }

    @Override // B2.E
    public long r() {
        return this.f2021e.r();
    }

    @Override // B2.E
    public x v() {
        return this.f2021e.v();
    }

    @Override // B2.E
    public k y() {
        return t.d(new C0032a(this.f2021e.y()));
    }

    /* JADX INFO: renamed from: O.a$a, reason: collision with other inner class name */
    private class C0032a implements F {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        k f2023b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        long f2024c = 0;

        C0032a(k kVar) {
            this.f2023b = kVar;
        }

        @Override // Q2.F
        public long R(i iVar, long j3) {
            long jR = this.f2023b.R(iVar, j3);
            this.f2024c += jR > 0 ? jR : 0L;
            f fVarI = g.i(a.this.f2019c);
            long jR2 = a.this.r();
            if (fVarI != null && jR2 != 0 && fVarI.a(this.f2024c / a.this.r())) {
                WritableMap writableMapCreateMap = Arguments.createMap();
                writableMapCreateMap.putString("taskId", a.this.f2019c);
                writableMapCreateMap.putString("written", String.valueOf(this.f2024c));
                writableMapCreateMap.putString("total", String.valueOf(a.this.r()));
                if (a.this.f2022f) {
                    writableMapCreateMap.putString("chunk", iVar.p0(Charset.defaultCharset()));
                } else {
                    writableMapCreateMap.putString("chunk", "");
                }
                ((DeviceEventManagerModule.RCTDeviceEventEmitter) a.this.f2020d.getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter.class)).emit("RNFetchBlobProgress", writableMapCreateMap);
            }
            return jR;
        }

        @Override // Q2.F
        public G f() {
            return null;
        }

        @Override // Q2.F, java.io.Closeable, java.lang.AutoCloseable
        public void close() {
        }
    }
}
