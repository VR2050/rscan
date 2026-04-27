package androidx.core.view;

import android.view.View;
import android.view.ViewGroup;
import java.util.Iterator;

/* JADX INFO: renamed from: androidx.core.view.b0, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public abstract class AbstractC0255b0 {

    /* JADX INFO: renamed from: androidx.core.view.b0$a */
    public static final class a implements y2.c {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ ViewGroup f4447a;

        a(ViewGroup viewGroup) {
            this.f4447a = viewGroup;
        }

        @Override // y2.c
        public Iterator iterator() {
            return AbstractC0255b0.b(this.f4447a);
        }
    }

    /* JADX INFO: renamed from: androidx.core.view.b0$b */
    public static final class b implements Iterator {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private int f4448a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ ViewGroup f4449b;

        b(ViewGroup viewGroup) {
            this.f4449b = viewGroup;
        }

        @Override // java.util.Iterator
        /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
        public View next() {
            ViewGroup viewGroup = this.f4449b;
            int i3 = this.f4448a;
            this.f4448a = i3 + 1;
            View childAt = viewGroup.getChildAt(i3);
            if (childAt != null) {
                return childAt;
            }
            throw new IndexOutOfBoundsException();
        }

        @Override // java.util.Iterator
        public boolean hasNext() {
            return this.f4448a < this.f4449b.getChildCount();
        }

        @Override // java.util.Iterator
        public void remove() {
            ViewGroup viewGroup = this.f4449b;
            int i3 = this.f4448a - 1;
            this.f4448a = i3;
            viewGroup.removeViewAt(i3);
        }
    }

    public static final y2.c a(ViewGroup viewGroup) {
        return new a(viewGroup);
    }

    public static final Iterator b(ViewGroup viewGroup) {
        return new b(viewGroup);
    }
}
