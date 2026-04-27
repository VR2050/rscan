package i2;

import java.util.AbstractCollection;
import java.util.Collection;

/* JADX INFO: renamed from: i2.c, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public abstract class AbstractC0575c extends AbstractCollection implements Collection {
    protected AbstractC0575c() {
    }

    public abstract int a();

    @Override // java.util.AbstractCollection, java.util.Collection
    public final /* bridge */ int size() {
        return a();
    }
}
