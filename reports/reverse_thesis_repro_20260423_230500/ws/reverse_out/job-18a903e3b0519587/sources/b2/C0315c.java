package b2;

import android.content.Context;
import com.facebook.soloader.C;
import com.facebook.soloader.C0497c;
import com.facebook.soloader.C0500f;
import com.facebook.soloader.E;
import com.facebook.soloader.G;
import com.facebook.soloader.p;
import java.io.File;
import java.util.ArrayList;

/* JADX INFO: renamed from: b2.c, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0315c implements InterfaceC0320h {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Context f5405a;

    public C0315c(Context context) {
        this.f5405a = context;
    }

    @Override // b2.InterfaceC0320h
    public boolean a(UnsatisfiedLinkError unsatisfiedLinkError, E[] eArr) {
        if (!(unsatisfiedLinkError instanceof C)) {
            return false;
        }
        p.b("SoLoader", "Checking /data/app missing libraries.");
        File file = new File(this.f5405a.getApplicationInfo().nativeLibraryDir);
        if (!file.exists()) {
            p.b("SoLoader", "Native library directory " + file + " does not exist, exiting /data/app recovery.");
            return false;
        }
        ArrayList arrayList = new ArrayList();
        int length = eArr.length;
        int i3 = 0;
        while (true) {
            if (i3 >= length) {
                break;
            }
            E e3 = eArr[i3];
            if (e3 instanceof C0497c) {
                C0497c c0497c = (C0497c) e3;
                try {
                    for (G.c cVar : c0497c.o()) {
                        if (!new File(file, cVar.f8323b).exists()) {
                            arrayList.add(cVar.f8323b);
                        }
                    }
                    if (arrayList.isEmpty()) {
                        p.b("SoLoader", "No libraries missing from " + file);
                        return false;
                    }
                    p.b("SoLoader", "Missing libraries from " + file + ": " + arrayList.toString() + ", will run prepare on tbe backup so source");
                    c0497c.e(0);
                } catch (Exception e4) {
                    p.c("SoLoader", "Encountered an exception while recovering from /data/app failure ", e4);
                    return false;
                }
            } else {
                i3++;
            }
        }
        for (E e5 : eArr) {
            if ((e5 instanceof C0500f) && !(e5 instanceof C0497c)) {
                ((C0500f) e5).h();
            }
        }
        p.b("SoLoader", "Successfully recovered from /data/app disk failure.");
        return true;
    }
}
