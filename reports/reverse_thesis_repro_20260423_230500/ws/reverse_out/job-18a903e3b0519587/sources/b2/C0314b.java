package b2;

import android.content.Context;
import com.facebook.soloader.E;
import com.facebook.soloader.p;
import com.facebook.soloader.v;
import java.io.File;

/* JADX INFO: renamed from: b2.b, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0314b implements InterfaceC0320h {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Context f5403a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final C0313a f5404b;

    public C0314b(Context context, C0313a c0313a) {
        this.f5403a = context;
        this.f5404b = c0313a;
    }

    @Override // b2.InterfaceC0320h
    public boolean a(UnsatisfiedLinkError unsatisfiedLinkError, E[] eArr) {
        String str = this.f5403a.getApplicationInfo().sourceDir;
        if (new File(str).exists()) {
            p.g("soloader.recovery.CheckBaseApkExists", "Base apk exists: " + str);
            return false;
        }
        StringBuilder sb = new StringBuilder("Base apk does not exist: ");
        sb.append(str);
        sb.append(". ");
        this.f5404b.b(sb);
        throw new v(sb.toString(), unsatisfiedLinkError);
    }
}
