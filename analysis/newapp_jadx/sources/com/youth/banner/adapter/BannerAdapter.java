package com.youth.banner.adapter;

import android.view.View;
import android.view.ViewGroup;
import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.RecyclerView.ViewHolder;
import com.youth.banner.C4179R;
import com.youth.banner.adapter.BannerAdapter;
import com.youth.banner.holder.IViewHolder;
import com.youth.banner.listener.OnBannerListener;
import com.youth.banner.util.BannerUtils;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public abstract class BannerAdapter<T, VH extends RecyclerView.ViewHolder> extends RecyclerView.Adapter<VH> implements IViewHolder<T, VH> {
    public List<T> mDatas = new ArrayList();
    private int mIncreaseCount = 2;
    private OnBannerListener<T> mOnBannerListener;
    private VH mViewHolder;

    public BannerAdapter(List<T> list) {
        setDatas(list);
    }

    /* renamed from: a */
    public /* synthetic */ void m4746a(Object obj, int i2, View view) {
        this.mOnBannerListener.OnBannerClick(obj, i2);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* renamed from: b */
    public /* synthetic */ void m4747b(RecyclerView.ViewHolder viewHolder, View view) {
        if (this.mOnBannerListener != null) {
            this.mOnBannerListener.OnBannerClick(viewHolder.itemView.getTag(C4179R.id.banner_data_key), ((Integer) viewHolder.itemView.getTag(C4179R.id.banner_pos_key)).intValue());
        }
    }

    public T getData(int i2) {
        return this.mDatas.get(i2);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemCount() {
        return getRealCount() > 1 ? getRealCount() + this.mIncreaseCount : getRealCount();
    }

    public int getRealCount() {
        List<T> list = this.mDatas;
        if (list == null) {
            return 0;
        }
        return list.size();
    }

    public T getRealData(int i2) {
        return this.mDatas.get(getRealPosition(i2));
    }

    public int getRealPosition(int i2) {
        return BannerUtils.getRealPosition(this.mIncreaseCount == 2, i2, getRealCount());
    }

    public VH getViewHolder() {
        return this.mViewHolder;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public final void onBindViewHolder(@NonNull VH vh, int i2) {
        this.mViewHolder = vh;
        final int realPosition = getRealPosition(i2);
        final T t = this.mDatas.get(realPosition);
        vh.itemView.setTag(C4179R.id.banner_data_key, t);
        vh.itemView.setTag(C4179R.id.banner_pos_key, Integer.valueOf(realPosition));
        onBindView(vh, this.mDatas.get(realPosition), realPosition, getRealCount());
        if (this.mOnBannerListener != null) {
            vh.itemView.setOnClickListener(new View.OnClickListener() { // from class: b.d0.a.a.b
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    BannerAdapter.this.m4746a(t, realPosition, view);
                }
            });
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    @NonNull
    public VH onCreateViewHolder(@NonNull ViewGroup viewGroup, int i2) {
        final VH vh = (VH) onCreateHolder(viewGroup, i2);
        vh.itemView.setOnClickListener(new View.OnClickListener() { // from class: b.d0.a.a.a
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                BannerAdapter.this.m4747b(vh, view);
            }
        });
        return vh;
    }

    public void setDatas(List<T> list) {
        if (list == null) {
            list = new ArrayList<>();
        }
        this.mDatas = list;
        notifyDataSetChanged();
    }

    public void setIncreaseCount(int i2) {
        this.mIncreaseCount = i2;
    }

    public void setOnBannerListener(OnBannerListener<T> onBannerListener) {
        this.mOnBannerListener = onBannerListener;
    }
}
