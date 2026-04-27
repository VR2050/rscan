package i2;

import java.util.AbstractSet;
import java.util.Set;

/* JADX INFO: renamed from: i2.e, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public abstract class AbstractC0577e extends AbstractSet implements Set {
    protected AbstractC0577e() {
    }

    public abstract int a();

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final /* bridge */ int size() {
        return a();
    }
}
