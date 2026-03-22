package com.jbzd.media.movecartoons.utils.banner;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import com.jbzd.media.movecartoons.bean.response.home.AdBean;
import com.jbzd.media.movecartoons.utils.banner.BannerAdapterImp3;
import com.qnmd.adnnm.da0yzo.R;
import com.youth.banner.adapter.BannerAdapter;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p006a.p007a.p008a.p009a.C0840d;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\u0018\u00002\u0014\u0012\n\u0012\b\u0012\u0004\u0012\u00020\u00030\u0002\u0012\u0004\u0012\u00020\u00040\u0001R\u0019\u0010\n\u001a\u00020\u00058\u0006@\u0006¢\u0006\f\n\u0004\b\u0006\u0010\u0007\u001a\u0004\b\b\u0010\t¨\u0006\u000b"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/utils/banner/BannerAdapterImp3;", "Lcom/youth/banner/adapter/BannerAdapter;", "", "Lcom/jbzd/media/movecartoons/bean/response/home/AdBean;", "Lcom/jbzd/media/movecartoons/utils/banner/BannerViewHolder3;", "Landroid/content/Context;", "c", "Landroid/content/Context;", "getContext", "()Landroid/content/Context;", "context", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class BannerAdapterImp3 extends BannerAdapter<List<? extends AdBean>, BannerViewHolder3> {

    /* renamed from: c, reason: from kotlin metadata */
    @NotNull
    public final Context context;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public BannerAdapterImp3(Context context, List bean, float f2, double d2, ImageView.ScaleType scaleType, int i2) {
        super(bean);
        int i3 = i2 & 4;
        int i4 = i2 & 8;
        int i5 = i2 & 16;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(bean, "bean");
        this.context = context;
    }

    @Override // com.youth.banner.holder.IViewHolder
    public void onBindView(Object obj, Object obj2, int i2, int i3) {
        BannerViewHolder3 holder = (BannerViewHolder3) obj;
        final List data = (List) obj2;
        Intrinsics.checkNotNullParameter(holder, "holder");
        Intrinsics.checkNotNullParameter(data, "data");
        if (i2 <= 0) {
            try {
                C2354n.m2455a2(this.context).m3298p(((AdBean) data.get(0)).content).m757R(holder.imageView);
                C2354n.m2455a2(this.context).m3298p(((AdBean) data.get(1)).content).m757R(holder.imageView2);
                C2354n.m2455a2(this.context).m3298p(((AdBean) data.get(2)).content).m757R(holder.imageView3);
            } catch (Exception unused) {
                return;
            }
        }
        if (i2 >= 1) {
            C2354n.m2455a2(this.context).m3298p(((AdBean) data.get(0)).content).m757R(holder.imageView);
            C2354n.m2455a2(this.context).m3298p(((AdBean) data.get(1)).content).m757R(holder.imageView2);
            C2354n.m2455a2(this.context).m3298p(((AdBean) data.get(2)).content).m757R(holder.imageView3);
        }
        holder.imageView.setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.a.o0.b
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                BannerAdapterImp3 this$0 = BannerAdapterImp3.this;
                List data2 = data;
                Intrinsics.checkNotNullParameter(this$0, "this$0");
                Intrinsics.checkNotNullParameter(data2, "$data");
                C0840d.f235a.m176b(this$0.context, (AdBean) data2.get(0));
            }
        });
        holder.imageView2.setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.a.o0.c
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                BannerAdapterImp3 this$0 = BannerAdapterImp3.this;
                List data2 = data;
                Intrinsics.checkNotNullParameter(this$0, "this$0");
                Intrinsics.checkNotNullParameter(data2, "$data");
                C0840d.f235a.m176b(this$0.context, (AdBean) data2.get(1));
            }
        });
        holder.imageView3.setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.a.o0.a
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                BannerAdapterImp3 this$0 = BannerAdapterImp3.this;
                List data2 = data;
                Intrinsics.checkNotNullParameter(this$0, "this$0");
                Intrinsics.checkNotNullParameter(data2, "$data");
                C0840d.f235a.m176b(this$0.context, (AdBean) data2.get(2));
            }
        });
    }

    @Override // com.youth.banner.holder.IViewHolder
    public Object onCreateHolder(ViewGroup parent, int i2) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        View views = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_banner3, parent, false);
        views.setLayoutParams(new ViewGroup.MarginLayoutParams(-1, -1));
        Intrinsics.checkNotNullExpressionValue(views, "views");
        return new BannerViewHolder3(views);
    }
}
