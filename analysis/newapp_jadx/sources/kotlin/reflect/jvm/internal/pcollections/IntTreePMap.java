package kotlin.reflect.jvm.internal.pcollections;

/* loaded from: classes.dex */
public final class IntTreePMap<V> {
    private static final IntTreePMap<Object> EMPTY = new IntTreePMap<>(IntTree.EMPTYNODE);
    private final IntTree<V> root;

    private IntTreePMap(IntTree<V> intTree) {
        this.root = intTree;
    }

    public static <V> IntTreePMap<V> empty() {
        return (IntTreePMap<V>) EMPTY;
    }

    private IntTreePMap<V> withRoot(IntTree<V> intTree) {
        return intTree == this.root ? this : new IntTreePMap<>(intTree);
    }

    public V get(int i2) {
        return this.root.get(i2);
    }

    public IntTreePMap<V> minus(int i2) {
        return withRoot(this.root.minus(i2));
    }

    public IntTreePMap<V> plus(int i2, V v) {
        return withRoot(this.root.plus(i2, v));
    }
}
