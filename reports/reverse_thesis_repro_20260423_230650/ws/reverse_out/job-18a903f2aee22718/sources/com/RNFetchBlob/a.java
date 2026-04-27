package com.RNFetchBlob;

import B2.C;
import B2.x;
import Q2.j;
import android.net.Uri;
import android.util.Base64;
import com.RNFetchBlob.g;
import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.modules.core.DeviceEventManagerModule;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;

/* JADX INFO: loaded from: classes.dex */
class a extends C {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private InputStream f5742b;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private ReadableArray f5744d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private String f5745e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private String f5746f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private g.e f5747g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private x f5748h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private File f5749i;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private long f5743c = 0;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    int f5750j = 0;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private Boolean f5751k = Boolean.FALSE;

    /* JADX INFO: renamed from: com.RNFetchBlob.a$a, reason: collision with other inner class name */
    static /* synthetic */ class C0090a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        static final /* synthetic */ int[] f5752a;

        static {
            int[] iArr = new int[g.e.values().length];
            f5752a = iArr;
            try {
                iArr[g.e.SingleFile.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                f5752a[g.e.AsIs.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                f5752a[g.e.Others.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
        }
    }

    private class b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public String f5753a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        String f5754b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        String f5755c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        public String f5756d;

        b(ReadableMap readableMap) {
            if (readableMap.hasKey("name")) {
                this.f5753a = readableMap.getString("name");
            }
            if (readableMap.hasKey("filename")) {
                this.f5754b = readableMap.getString("filename");
            }
            if (readableMap.hasKey("type")) {
                this.f5755c = readableMap.getString("type");
            } else {
                this.f5755c = this.f5754b == null ? "text/plain" : "application/octet-stream";
            }
            if (readableMap.hasKey("data")) {
                this.f5756d = readableMap.getString("data");
            }
        }
    }

    a(String str) {
        this.f5745e = str;
    }

    private ArrayList k() throws IOException {
        int length;
        long length2;
        ArrayList arrayList = new ArrayList();
        ReactApplicationContext reactApplicationContext = RNFetchBlob.RCTContext;
        long jAvailable = 0;
        for (int i3 = 0; i3 < this.f5744d.size(); i3++) {
            b bVar = new b(this.f5744d.getMap(i3));
            arrayList.add(bVar);
            String str = bVar.f5756d;
            if (str == null) {
                h.a("RNFetchBlob multipart request builder has found a field without `data` property, the field `" + bVar.f5753a + "` will be removed implicitly.");
            } else {
                if (bVar.f5754b != null) {
                    if (str.startsWith("RNFetchBlob-file://")) {
                        String strW = d.w(str.substring(19));
                        if (d.q(strW)) {
                            try {
                                length = reactApplicationContext.getAssets().open(strW.replace("bundle-assets://", "")).available();
                            } catch (IOException e3) {
                                h.a(e3.getLocalizedMessage());
                            }
                        } else {
                            length2 = new File(d.w(strW)).length();
                        }
                    } else if (str.startsWith("RNFetchBlob-content://")) {
                        String strSubstring = str.substring(22);
                        InputStream inputStreamOpenInputStream = null;
                        try {
                            try {
                                inputStreamOpenInputStream = reactApplicationContext.getContentResolver().openInputStream(Uri.parse(strSubstring));
                                jAvailable += (long) inputStreamOpenInputStream.available();
                            } catch (Throwable th) {
                                if (inputStreamOpenInputStream != null) {
                                    inputStreamOpenInputStream.close();
                                }
                                throw th;
                            }
                        } catch (Exception e4) {
                            h.a("Failed to estimate form data length from content URI:" + strSubstring + ", " + e4.getLocalizedMessage());
                            if (inputStreamOpenInputStream != null) {
                            }
                        }
                        inputStreamOpenInputStream.close();
                    } else {
                        length = Base64.decode(str, 0).length;
                    }
                    jAvailable += length2;
                } else {
                    length = str.getBytes().length;
                }
                length2 = length;
                jAvailable += length2;
            }
        }
        this.f5743c = jAvailable;
        return arrayList;
    }

    /* JADX WARN: Removed duplicated region for block: B:28:0x014a A[DONT_GENERATE, PHI: r10
      0x014a: PHI (r10v5 java.io.InputStream) = (r10v4 java.io.InputStream), (r10v6 java.io.InputStream) binds: [B:33:0x016f, B:27:0x0148] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private java.io.File l() throws java.io.IOException {
        /*
            Method dump skipped, instruction units count: 490
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.RNFetchBlob.a.l():java.io.File");
    }

    private void m(long j3) {
        f fVarJ = g.j(this.f5745e);
        if (fVarJ != null) {
            long j4 = this.f5743c;
            if (j4 == 0 || !fVarJ.a(j3 / j4)) {
                return;
            }
            WritableMap writableMapCreateMap = Arguments.createMap();
            writableMapCreateMap.putString("taskId", this.f5745e);
            writableMapCreateMap.putString("written", String.valueOf(j3));
            writableMapCreateMap.putString("total", String.valueOf(this.f5743c));
            ((DeviceEventManagerModule.RCTDeviceEventEmitter) RNFetchBlob.RCTContext.getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter.class)).emit("RNFetchBlobProgress-upload", writableMapCreateMap);
        }
    }

    private InputStream n() throws Exception {
        if (!this.f5746f.startsWith("RNFetchBlob-file://")) {
            if (!this.f5746f.startsWith("RNFetchBlob-content://")) {
                try {
                    return new ByteArrayInputStream(Base64.decode(this.f5746f, 0));
                } catch (Exception e3) {
                    throw new Exception("error when getting request stream: " + e3.getLocalizedMessage());
                }
            }
            String strSubstring = this.f5746f.substring(22);
            try {
                return RNFetchBlob.RCTContext.getContentResolver().openInputStream(Uri.parse(strSubstring));
            } catch (Exception e4) {
                throw new Exception("error when getting request stream for content URI: " + strSubstring, e4);
            }
        }
        String strW = d.w(this.f5746f.substring(19));
        if (d.q(strW)) {
            try {
                return RNFetchBlob.RCTContext.getAssets().open(strW.replace("bundle-assets://", ""));
            } catch (Exception e5) {
                throw new Exception("error when getting request stream from asset : " + e5.getLocalizedMessage());
            }
        }
        File file = new File(d.w(strW));
        try {
            if (!file.exists()) {
                file.createNewFile();
            }
            return new FileInputStream(file);
        } catch (Exception e6) {
            throw new Exception("error when getting request stream: " + e6.getLocalizedMessage());
        }
    }

    private void o(InputStream inputStream, FileOutputStream fileOutputStream) throws IOException {
        byte[] bArr = new byte[10240];
        while (true) {
            int i3 = inputStream.read(bArr);
            if (i3 <= 0) {
                inputStream.close();
                return;
            }
            fileOutputStream.write(bArr, 0, i3);
        }
    }

    private void p(InputStream inputStream, j jVar) throws IOException {
        byte[] bArr = new byte[10240];
        long j3 = 0;
        while (true) {
            int i3 = inputStream.read(bArr, 0, 10240);
            if (i3 <= 0) {
                inputStream.close();
                return;
            } else {
                jVar.j(bArr, 0, i3);
                j3 += (long) i3;
                m(j3);
            }
        }
    }

    @Override // B2.C
    public long a() {
        if (this.f5751k.booleanValue()) {
            return -1L;
        }
        return this.f5743c;
    }

    @Override // B2.C
    public x b() {
        return this.f5748h;
    }

    @Override // B2.C
    public void h(j jVar) {
        try {
            p(this.f5742b, jVar);
        } catch (Exception e3) {
            h.a(e3.getLocalizedMessage());
            e3.printStackTrace();
        }
    }

    a i(boolean z3) {
        this.f5751k = Boolean.valueOf(z3);
        return this;
    }

    boolean j() {
        try {
            File file = this.f5749i;
            if (file == null || !file.exists()) {
                return true;
            }
            this.f5749i.delete();
            return true;
        } catch (Exception e3) {
            h.a(e3.getLocalizedMessage());
            return false;
        }
    }

    a q(ReadableArray readableArray) {
        this.f5744d = readableArray;
        try {
            this.f5749i = l();
            this.f5742b = new FileInputStream(this.f5749i);
            this.f5743c = this.f5749i.length();
        } catch (Exception e3) {
            e3.printStackTrace();
            h.a("RNFetchBlob failed to create request multipart body :" + e3.getLocalizedMessage());
        }
        return this;
    }

    a r(String str) {
        this.f5746f = str;
        if (str == null) {
            this.f5746f = "";
            this.f5747g = g.e.AsIs;
        }
        try {
            int i3 = C0090a.f5752a[this.f5747g.ordinal()];
            if (i3 == 1) {
                this.f5742b = n();
                this.f5743c = r3.available();
            } else if (i3 == 2) {
                this.f5743c = this.f5746f.getBytes().length;
                this.f5742b = new ByteArrayInputStream(this.f5746f.getBytes());
            }
        } catch (Exception e3) {
            e3.printStackTrace();
            h.a("RNFetchBlob failed to create single content request body :" + e3.getLocalizedMessage() + "\r\n");
        }
        return this;
    }

    a s(x xVar) {
        this.f5748h = xVar;
        return this;
    }

    a t(g.e eVar) {
        this.f5747g = eVar;
        return this;
    }
}
