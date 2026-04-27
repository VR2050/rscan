package b2;

import android.content.Context;
import com.facebook.soloader.E;
import com.facebook.soloader.p;
import com.facebook.soloader.w;
import java.io.File;

/* JADX INFO: renamed from: b2.g, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0319g implements InterfaceC0320h {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Context f5411a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final C0313a f5412b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final int f5413c;

    public C0319g(Context context, C0313a c0313a) {
        this.f5411a = context;
        this.f5412b = c0313a;
        this.f5413c = c0313a.c();
    }

    private boolean b() {
        String strC = c();
        return new File(strC).exists() && this.f5412b.a(strC);
    }

    private String c() {
        return this.f5411a.getApplicationInfo().sourceDir;
    }

    /* JADX WARN: Multi-variable type inference failed */
    private void d(E[] eArr) {
        for (int i3 = 0; i3 < eArr.length; i3++) {
            Object[] objArr = eArr[i3];
            if (objArr instanceof w) {
                eArr[i3] = ((w) objArr).a(this.f5411a);
            }
        }
    }

    @Override // b2.InterfaceC0320h
    public boolean a(UnsatisfiedLinkError unsatisfiedLinkError, E[] eArr) {
        if (b()) {
            d(eArr);
            return true;
        }
        if (this.f5413c == this.f5412b.c()) {
            return false;
        }
        p.g("soloader.recovery.DetectDataAppMove", "Context was updated (perhaps by another thread)");
        return true;
    }
}
