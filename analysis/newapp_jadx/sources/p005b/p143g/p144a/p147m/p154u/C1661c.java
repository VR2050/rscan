package p005b.p143g.p144a.p147m.p154u;

import android.util.Log;
import androidx.annotation.NonNull;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.InterfaceC1572d;
import p005b.p143g.p144a.p170s.C1799a;

/* renamed from: b.g.a.m.u.c */
/* loaded from: classes.dex */
public class C1661c implements InterfaceC1572d<ByteBuffer> {
    @Override // p005b.p143g.p144a.p147m.InterfaceC1572d
    /* renamed from: a */
    public boolean mo822a(@NonNull ByteBuffer byteBuffer, @NonNull File file, @NonNull C1582n c1582n) {
        try {
            C1799a.m1135b(byteBuffer, file);
            return true;
        } catch (IOException unused) {
            Log.isLoggable("ByteBufferEncoder", 3);
            return false;
        }
    }
}
