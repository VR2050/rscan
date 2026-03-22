package me.jingbin.library.adapter;

import android.util.SparseArray;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;
import java.util.List;

/* loaded from: classes3.dex */
public abstract class BaseByViewHolder<T> extends RecyclerView.ViewHolder {
    public BaseByViewHolder(ViewGroup viewGroup, int i2) {
        super(LayoutInflater.from(viewGroup.getContext()).inflate(i2, viewGroup, false));
        new SparseArray();
    }

    /* renamed from: a */
    public abstract void mo5629a(BaseByViewHolder<T> baseByViewHolder, T t, int i2);

    /* renamed from: b */
    public void mo5634b(BaseByViewHolder<T> baseByViewHolder, T t, int i2, @NonNull List<Object> list) {
        mo5629a(baseByViewHolder, t, i2);
    }

    public BaseByViewHolder(@NonNull View view) {
        super(view);
        new SparseArray();
    }
}
