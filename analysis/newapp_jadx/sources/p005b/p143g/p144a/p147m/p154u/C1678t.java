package p005b.p143g.p144a.p147m.p154u;

import android.util.Log;
import androidx.annotation.NonNull;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.InterfaceC1572d;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1612b;

/* renamed from: b.g.a.m.u.t */
/* loaded from: classes.dex */
public class C1678t implements InterfaceC1572d<InputStream> {

    /* renamed from: a */
    public final InterfaceC1612b f2412a;

    public C1678t(InterfaceC1612b interfaceC1612b) {
        this.f2412a = interfaceC1612b;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v1 */
    /* JADX WARN: Type inference failed for: r1v2 */
    /* JADX WARN: Type inference failed for: r1v3, types: [java.io.OutputStream] */
    /* JADX WARN: Type inference failed for: r1v4 */
    /* JADX WARN: Type inference failed for: r1v5 */
    /* JADX WARN: Type inference failed for: r1v6 */
    /* JADX WARN: Type inference failed for: r1v7 */
    /* JADX WARN: Type inference failed for: r1v8 */
    /* JADX WARN: Type inference failed for: r1v9 */
    @Override // p005b.p143g.p144a.p147m.InterfaceC1572d
    /* renamed from: a */
    public boolean mo822a(@NonNull InputStream inputStream, @NonNull File file, @NonNull C1582n c1582n) {
        FileOutputStream fileOutputStream;
        InputStream inputStream2 = inputStream;
        byte[] bArr = (byte[]) this.f2412a.mo863d(65536, byte[].class);
        boolean z = false;
        ?? r1 = 0;
        r1 = 0;
        try {
            try {
                try {
                    fileOutputStream = new FileOutputStream(file);
                    while (true) {
                        try {
                            int read = inputStream2.read(bArr);
                            r1 = -1;
                            if (read == -1) {
                                break;
                            }
                            fileOutputStream.write(bArr, 0, read);
                        } catch (IOException unused) {
                            r1 = fileOutputStream;
                            Log.isLoggable("StreamEncoder", 3);
                            if (r1 != 0) {
                                r1.close();
                                r1 = r1;
                            }
                            this.f2412a.put(bArr);
                            return z;
                        } catch (Throwable th) {
                            th = th;
                            if (fileOutputStream != null) {
                                try {
                                    fileOutputStream.close();
                                } catch (IOException unused2) {
                                }
                            }
                            this.f2412a.put(bArr);
                            throw th;
                        }
                    }
                    fileOutputStream.close();
                    z = true;
                    fileOutputStream.close();
                } catch (IOException unused3) {
                }
            } catch (IOException unused4) {
            }
            this.f2412a.put(bArr);
            return z;
        } catch (Throwable th2) {
            th = th2;
            fileOutputStream = r1;
        }
    }
}
