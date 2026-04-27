package E;

import androidx.lifecycle.z;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import r2.AbstractC0677a;
import s2.l;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class c {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final List f612a = new ArrayList();

    public final void a(x2.b bVar, l lVar) {
        j.f(bVar, "clazz");
        j.f(lVar, "initializer");
        this.f612a.add(new f(AbstractC0677a.a(bVar), lVar));
    }

    public final z.b b() {
        f[] fVarArr = (f[]) this.f612a.toArray(new f[0]);
        return new b((f[]) Arrays.copyOf(fVarArr, fVarArr.length));
    }
}
