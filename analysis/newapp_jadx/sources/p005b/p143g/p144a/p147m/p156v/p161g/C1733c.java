package p005b.p143g.p144a.p147m.p156v.p161g;

import android.util.Log;
import androidx.annotation.NonNull;
import com.bumptech.glide.load.resource.gif.GifDrawable;
import java.io.File;
import java.io.IOException;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.EnumC1571c;
import p005b.p143g.p144a.p147m.InterfaceC1585q;
import p005b.p143g.p144a.p147m.p150t.InterfaceC1655w;
import p005b.p143g.p144a.p170s.C1799a;

/* renamed from: b.g.a.m.v.g.c */
/* loaded from: classes.dex */
public class C1733c implements InterfaceC1585q<GifDrawable> {
    @Override // p005b.p143g.p144a.p147m.InterfaceC1572d
    /* renamed from: a */
    public boolean mo822a(@NonNull Object obj, @NonNull File file, @NonNull C1582n c1582n) {
        try {
            C1799a.m1135b(((GifDrawable) ((InterfaceC1655w) obj).get()).f8843c.f8854a.f2567a.mo808e().asReadOnlyBuffer(), file);
            return true;
        } catch (IOException unused) {
            Log.isLoggable("GifEncoder", 5);
            return false;
        }
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1585q
    @NonNull
    /* renamed from: b */
    public EnumC1571c mo831b(@NonNull C1582n c1582n) {
        return EnumC1571c.SOURCE;
    }
}
