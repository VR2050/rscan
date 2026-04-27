package E;

import androidx.lifecycle.y;
import androidx.lifecycle.z;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class b implements z.b {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final f[] f611b;

    public b(f... fVarArr) {
        j.f(fVarArr, "initializers");
        this.f611b = fVarArr;
    }

    @Override // androidx.lifecycle.z.b
    public y b(Class cls, a aVar) {
        j.f(cls, "modelClass");
        j.f(aVar, "extras");
        y yVar = null;
        for (f fVar : this.f611b) {
            if (j.b(fVar.a(), cls)) {
                Object objD = fVar.b().d(aVar);
                yVar = objD instanceof y ? (y) objD : null;
            }
        }
        if (yVar != null) {
            return yVar;
        }
        throw new IllegalArgumentException("No initializer set for given class " + cls.getName());
    }
}
