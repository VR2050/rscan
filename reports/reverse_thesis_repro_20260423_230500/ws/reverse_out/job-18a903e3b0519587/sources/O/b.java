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
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

/* JADX INFO: loaded from: classes.dex */
public class b extends E {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    String f2026c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    E f2027d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    String f2028e;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    ReactApplicationContext f2030g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    FileOutputStream f2031h;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    long f2029f = 0;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    boolean f2032i = false;

    private class a implements F {
        private void b(String str, long j3, long j4) {
            WritableMap writableMapCreateMap = Arguments.createMap();
            writableMapCreateMap.putString("taskId", str);
            writableMapCreateMap.putString("written", String.valueOf(j3));
            writableMapCreateMap.putString("total", String.valueOf(j4));
            ((DeviceEventManagerModule.RCTDeviceEventEmitter) b.this.f2030g.getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter.class)).emit("RNFetchBlobProgress", writableMapCreateMap);
        }

        @Override // Q2.F
        public long R(i iVar, long j3) {
            float fR;
            int i3 = (int) j3;
            try {
                byte[] bArr = new byte[i3];
                long j4 = b.this.f2027d.b().read(bArr, 0, i3);
                b bVar = b.this;
                bVar.f2029f += j4 > 0 ? j4 : 0L;
                if (j4 > 0) {
                    bVar.f2031h.write(bArr, 0, (int) j4);
                } else if (bVar.r() == -1 && j4 == -1) {
                    b.this.f2032i = true;
                }
                f fVarI = g.i(b.this.f2026c);
                if (b.this.r() != 0) {
                    if (b.this.r() != -1) {
                        b bVar2 = b.this;
                        fR = bVar2.f2029f / bVar2.r();
                    } else {
                        fR = b.this.f2032i ? 1.0f : 0.0f;
                    }
                    if (fVarI != null && fVarI.a(fR)) {
                        if (b.this.r() != -1) {
                            b bVar3 = b.this;
                            b(bVar3.f2026c, bVar3.f2029f, bVar3.r());
                        } else {
                            b bVar4 = b.this;
                            if (bVar4.f2032i) {
                                String str = bVar4.f2026c;
                                long j5 = bVar4.f2029f;
                                b(str, j5, j5);
                            } else {
                                b(bVar4.f2026c, 0L, bVar4.r());
                            }
                        }
                    }
                }
                return j4;
            } catch (Exception unused) {
                return -1L;
            }
        }

        @Override // Q2.F, java.io.Closeable, java.lang.AutoCloseable
        public void close() throws IOException {
            b.this.f2031h.close();
        }

        @Override // Q2.F
        public G f() {
            return null;
        }

        private a() {
        }
    }

    public b(ReactApplicationContext reactApplicationContext, String str, E e3, String str2, boolean z3) throws IOException {
        this.f2030g = reactApplicationContext;
        this.f2026c = str;
        this.f2027d = e3;
        this.f2028e = str2;
        if (str2 != null) {
            boolean z4 = !z3;
            String strReplace = str2.replace("?append=true", "");
            this.f2028e = strReplace;
            File file = new File(strReplace);
            File parentFile = file.getParentFile();
            if (parentFile == null || parentFile.exists() || parentFile.mkdirs()) {
                if (!file.exists()) {
                    file.createNewFile();
                }
                this.f2031h = new FileOutputStream(new File(strReplace), z4);
            } else {
                throw new IllegalStateException("Couldn't create dir: " + parentFile);
            }
        }
    }

    public boolean D() {
        return this.f2029f == r() || (r() == -1 && this.f2032i);
    }

    @Override // B2.E
    public long r() {
        return this.f2027d.r();
    }

    @Override // B2.E
    public x v() {
        return this.f2027d.v();
    }

    @Override // B2.E
    public k y() {
        return t.d(new a());
    }
}
