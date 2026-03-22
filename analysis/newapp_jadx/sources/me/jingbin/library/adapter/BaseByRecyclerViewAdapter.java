package me.jingbin.library.adapter;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import me.jingbin.library.ByRecyclerView;
import me.jingbin.library.adapter.BaseByViewHolder;

/* loaded from: classes3.dex */
public abstract class BaseByRecyclerViewAdapter<T, K extends BaseByViewHolder> extends RecyclerView.Adapter<K> {

    /* renamed from: a */
    public ByRecyclerView f12717a;

    /* renamed from: b */
    public List<T> f12718b = new ArrayList();

    /* renamed from: a */
    public int m5633a() {
        ByRecyclerView byRecyclerView = this.f12717a;
        if (byRecyclerView != null) {
            return byRecyclerView.getCustomTopItemViewCount();
        }
        return 0;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemCount() {
        if (this.f12718b == null) {
            this.f12718b = new ArrayList();
        }
        return this.f12718b.size();
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public void onBindViewHolder(@NonNull RecyclerView.ViewHolder viewHolder, int i2) {
        BaseByViewHolder<T> baseByViewHolder = (BaseByViewHolder) viewHolder;
        Objects.requireNonNull(baseByViewHolder);
        baseByViewHolder.mo5629a(baseByViewHolder, this.f12718b.get(i2), i2);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public void onBindViewHolder(@NonNull RecyclerView.ViewHolder viewHolder, int i2, @NonNull List list) {
        BaseByViewHolder<T> baseByViewHolder = (BaseByViewHolder) viewHolder;
        Objects.requireNonNull(baseByViewHolder);
        if (list.isEmpty()) {
            baseByViewHolder.mo5629a(baseByViewHolder, this.f12718b.get(i2), i2);
        } else {
            baseByViewHolder.mo5634b(baseByViewHolder, this.f12718b.get(i2), i2, list);
        }
    }
}
