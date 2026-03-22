package com.jbzd.media.movecartoons.utils.banner;

import android.content.Context;
import android.view.ViewGroup;
import android.widget.ImageView;
import com.google.android.material.shadow.ShadowDrawableWrapper;
import com.qnmd.adnnm.da0yzo.R;
import com.youth.banner.adapter.BannerAdapter;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0859m0;
import p005b.p143g.p144a.C1558h;
import p005b.p143g.p144a.p146l.C1568e;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p336c.C2851b;
import p005b.p327w.p330b.p336c.C2853d;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0002\u0010\u0007\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0006\n\u0002\b\u0004\u0018\u00002\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00030\u0001R\u0016\u0010\u0007\u001a\u00020\u00048\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\u0005\u0010\u0006R\u0019\u0010\r\u001a\u00020\b8\u0006@\u0006¢\u0006\f\n\u0004\b\t\u0010\n\u001a\u0004\b\u000b\u0010\fR\u0018\u0010\u0011\u001a\u0004\u0018\u00010\u000e8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\u000f\u0010\u0010R\u0016\u0010\u0015\u001a\u00020\u00128\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\u0013\u0010\u0014¨\u0006\u0016"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/utils/banner/BannerAdapterImp;", "Lcom/youth/banner/adapter/BannerAdapter;", "", "Lcom/jbzd/media/movecartoons/utils/banner/BannerViewHolder;", "", C1568e.f1949a, "F", "horizontalPadding", "Landroid/content/Context;", "c", "Landroid/content/Context;", "getContext", "()Landroid/content/Context;", "context", "Landroid/widget/ImageView$ScaleType;", "g", "Landroid/widget/ImageView$ScaleType;", "scaleType", "", "f", "D", "viewRoundDp", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class BannerAdapterImp extends BannerAdapter<String, BannerViewHolder> {

    /* renamed from: c, reason: from kotlin metadata */
    @NotNull
    public final Context context;

    /* renamed from: e, reason: from kotlin metadata */
    public final float horizontalPadding;

    /* renamed from: f, reason: from kotlin metadata */
    public final double viewRoundDp;

    /* renamed from: g, reason: from kotlin metadata */
    @Nullable
    public final ImageView.ScaleType scaleType;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public BannerAdapterImp(Context context, List imageUrls, float f2, double d2, ImageView.ScaleType scaleType, int i2) {
        super(imageUrls);
        f2 = (i2 & 4) != 0 ? 0.0f : f2;
        d2 = (i2 & 8) != 0 ? 10.0d : d2;
        scaleType = (i2 & 16) != 0 ? null : scaleType;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(imageUrls, "imageUrls");
        this.context = context;
        this.horizontalPadding = f2;
        this.viewRoundDp = d2;
        this.scaleType = scaleType;
    }

    @Override // com.youth.banner.holder.IViewHolder
    public void onBindView(Object obj, Object obj2, int i2, int i3) {
        BannerViewHolder holder = (BannerViewHolder) obj;
        String data = (String) obj2;
        Intrinsics.checkNotNullParameter(holder, "holder");
        Intrinsics.checkNotNullParameter(data, "data");
        double d2 = this.viewRoundDp;
        if (d2 == 99.0d) {
            C1558h mo770c = C2354n.m2455a2(this.context).mo770c();
            mo770c.mo763X(data);
            ((C2851b) mo770c).m3292f0().m757R(holder.imageView);
            return;
        }
        if (d2 == 88.0d) {
            C1558h mo770c2 = C2354n.m2455a2(this.context).mo770c();
            mo770c2.mo763X(data);
            C2853d c2853d = C2853d.f7770a;
            int i4 = C2853d.f7777h;
            ((C2851b) ((C2851b) mo770c2).mo1098y(i4).mo1088l(i4).mo1083d()).m757R(holder.imageView);
            return;
        }
        if (d2 == 1.0d) {
            C1558h mo770c3 = C2354n.m2455a2(this.context).mo770c();
            mo770c3.mo763X(data);
            ((C2851b) mo770c3).m3291e0(R.drawable.ic_holder_ad200_51).m757R(holder.imageView);
        } else {
            C1558h mo770c4 = C2354n.m2455a2(this.context).mo770c();
            mo770c4.mo763X(data);
            ((C2851b) mo770c4).m3295i0().m757R(holder.imageView);
        }
    }

    @Override // com.youth.banner.holder.IViewHolder
    public Object onCreateHolder(ViewGroup parent, int i2) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        ImageView view = new ImageView(parent.getContext());
        ViewGroup.MarginLayoutParams marginLayoutParams = new ViewGroup.MarginLayoutParams(-1, -1);
        float f2 = this.horizontalPadding;
        if (f2 > 0.0f) {
            marginLayoutParams.setMargins(C2354n.m2425R(this.context, f2), 0, C2354n.m2425R(this.context, this.horizontalPadding), 0);
        }
        Unit unit = Unit.INSTANCE;
        view.setLayoutParams(marginLayoutParams);
        ImageView.ScaleType scaleType = this.scaleType;
        if (scaleType == null) {
            scaleType = ImageView.ScaleType.FIT_XY;
        }
        view.setScaleType(scaleType);
        double d2 = this.viewRoundDp;
        if (d2 > ShadowDrawableWrapper.COS_45) {
            if (!(d2 == 99.0d)) {
                if (!(d2 == 88.0d)) {
                    Intrinsics.checkNotNullParameter(view, "view");
                    view.setOutlineProvider(new C0859m0(d2));
                    view.setClipToOutline(true);
                }
            }
        }
        return new BannerViewHolder(view);
    }
}
