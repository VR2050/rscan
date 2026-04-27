package im.uwrkaxlmjj.ui.components.banner.adapter;

import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.RecyclerView.ViewHolder;
import im.uwrkaxlmjj.ui.components.banner.holder.IViewHolder;
import im.uwrkaxlmjj.ui.components.banner.listener.OnBannerListener;
import im.uwrkaxlmjj.ui.components.banner.util.BannerUtils;
import java.util.ArrayList;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public abstract class BannerAdapter<T, VH extends RecyclerView.ViewHolder> extends RecyclerView.Adapter<VH> implements IViewHolder<T, VH> {
    protected List<T> mDatas = new ArrayList();
    private int mIncreaseCount = 2;
    private OnBannerListener<T> mOnBannerListener;
    private VH mViewHolder;

    public BannerAdapter(List<T> datas) {
        setDatas(datas);
    }

    public void setDatas(List<T> datas) {
        if (datas == null) {
            datas = new ArrayList();
        }
        this.mDatas = datas;
        notifyDataSetChanged();
    }

    public T getData(int position) {
        return this.mDatas.get(position);
    }

    public T getRealData(int position) {
        return this.mDatas.get(getRealPosition(position));
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public final void onBindViewHolder(VH holder, int position) {
        this.mViewHolder = holder;
        final int real = getRealPosition(position);
        final T data = this.mDatas.get(real);
        holder.itemView.setTag(R.attr.banner_data_key, data);
        holder.itemView.setTag(R.attr.banner_pos_key, Integer.valueOf(real));
        onBindView(holder, this.mDatas.get(real), real, getRealCount());
        if (this.mOnBannerListener != null) {
            holder.itemView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.banner.adapter.-$$Lambda$BannerAdapter$-HuzfvbmhWc7w2n0oaTL0cY0uao
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$onBindViewHolder$0$BannerAdapter(data, real, view);
                }
            });
        }
    }

    public /* synthetic */ void lambda$onBindViewHolder$0$BannerAdapter(Object data, int real, View view) {
        this.mOnBannerListener.OnBannerClick(data, real);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public VH onCreateViewHolder(ViewGroup parent, int viewType) {
        final VH vh = onCreateHolder(parent, viewType);
        vh.itemView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.banner.adapter.-$$Lambda$BannerAdapter$A4ntNO1uLIUJuOW1cStw3K41hAE
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$onCreateViewHolder$1$BannerAdapter(vh, view);
            }
        });
        return vh;
    }

    /* JADX WARN: Type inference fix 'apply assigned field type' failed
    java.lang.UnsupportedOperationException: ArgType.getObject(), call class: class jadx.core.dex.instructions.args.ArgType$PrimitiveArg
    	at jadx.core.dex.instructions.args.ArgType.getObject(ArgType.java:593)
    	at jadx.core.dex.attributes.nodes.ClassTypeVarsAttr.getTypeVarsMapFor(ClassTypeVarsAttr.java:35)
    	at jadx.core.dex.nodes.utils.TypeUtils.replaceClassGenerics(TypeUtils.java:177)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.insertExplicitUseCast(FixTypesVisitor.java:397)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.tryFieldTypeWithNewCasts(FixTypesVisitor.java:359)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.applyFieldType(FixTypesVisitor.java:309)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.visit(FixTypesVisitor.java:94)
     */
    public /* synthetic */ void lambda$onCreateViewHolder$1$BannerAdapter(RecyclerView.ViewHolder viewHolder, View view) {
        if (this.mOnBannerListener != null) {
            Object tag = viewHolder.itemView.getTag(R.attr.banner_data_key);
            this.mOnBannerListener.OnBannerClick((T) tag, ((Integer) viewHolder.itemView.getTag(R.attr.banner_pos_key)).intValue());
        }
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

    public int getRealPosition(int position) {
        return BannerUtils.getRealPosition(this.mIncreaseCount == 2, position, getRealCount());
    }

    public void setOnBannerListener(OnBannerListener<T> listener) {
        this.mOnBannerListener = listener;
    }

    public VH getViewHolder() {
        return this.mViewHolder;
    }

    public void setIncreaseCount(int increaseCount) {
        this.mIncreaseCount = increaseCount;
    }
}
