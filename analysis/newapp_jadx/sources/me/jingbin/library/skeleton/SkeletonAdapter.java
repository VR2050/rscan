package me.jingbin.library.skeleton;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.RecyclerView;

/* loaded from: classes3.dex */
public class SkeletonAdapter extends RecyclerView.Adapter<RecyclerView.ViewHolder> {

    /* renamed from: me.jingbin.library.skeleton.SkeletonAdapter$a */
    public class C4972a extends RecyclerView.ViewHolder {
        public C4972a(SkeletonAdapter skeletonAdapter, View view) {
            super(view);
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemCount() {
        return 0;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public long getItemId(int i2) {
        return i2;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemViewType(int i2) {
        return super.getItemViewType(i2);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public void onBindViewHolder(RecyclerView.ViewHolder viewHolder, int i2) {
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup viewGroup, int i2) {
        return new C4972a(this, LayoutInflater.from(viewGroup.getContext()).inflate(0, viewGroup, false));
    }
}
