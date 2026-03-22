package me.jingbin.library.adapter;

import android.view.ViewGroup;
import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;
import java.util.List;

/* loaded from: classes3.dex */
public abstract class BaseRecyclerAdapter<T> extends BaseByRecyclerViewAdapter<T, BaseByViewHolder<T>> {

    /* renamed from: me.jingbin.library.adapter.BaseRecyclerAdapter$a */
    public class C4969a extends BaseByViewHolder<T> {
        public C4969a(ViewGroup viewGroup, int i2) {
            super(viewGroup, i2);
        }

        @Override // me.jingbin.library.adapter.BaseByViewHolder
        /* renamed from: a */
        public void mo5629a(BaseByViewHolder<T> baseByViewHolder, T t, int i2) {
            BaseRecyclerAdapter.this.m5635b(baseByViewHolder, t, i2);
        }

        @Override // me.jingbin.library.adapter.BaseByViewHolder
        /* renamed from: b */
        public void mo5634b(BaseByViewHolder<T> baseByViewHolder, T t, int i2, @NonNull List<Object> list) {
            BaseRecyclerAdapter.this.m5636c(baseByViewHolder, t, i2);
        }
    }

    /* renamed from: b */
    public abstract void m5635b(BaseByViewHolder<T> baseByViewHolder, T t, int i2);

    /* JADX WARN: Multi-variable type inference failed */
    /* renamed from: c */
    public void m5636c(BaseByViewHolder baseByViewHolder, Object obj, int i2) {
        m5635b(baseByViewHolder, obj, i2);
    }

    @NonNull
    /* renamed from: d */
    public BaseByViewHolder m5637d(@NonNull ViewGroup viewGroup) {
        return new C4969a(viewGroup, 0);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    @NonNull
    public /* bridge */ /* synthetic */ RecyclerView.ViewHolder onCreateViewHolder(@NonNull ViewGroup viewGroup, int i2) {
        return m5637d(viewGroup);
    }
}
