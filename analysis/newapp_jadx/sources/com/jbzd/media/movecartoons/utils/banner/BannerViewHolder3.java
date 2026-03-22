package com.jbzd.media.movecartoons.utils.banner;

import android.view.View;
import android.widget.ImageView;
import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;
import com.qnmd.adnnm.da0yzo.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u000f\n\u0002\u0018\u0002\n\u0002\b\u0004\u0018\u00002\u00020\u0001B\u0011\u0012\b\b\u0001\u0010\u0013\u001a\u00020\u0012¢\u0006\u0004\b\u0014\u0010\u0015R\"\u0010\t\u001a\u00020\u00028\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u0003\u0010\u0004\u001a\u0004\b\u0005\u0010\u0006\"\u0004\b\u0007\u0010\bR\"\u0010\r\u001a\u00020\u00028\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\n\u0010\u0004\u001a\u0004\b\u000b\u0010\u0006\"\u0004\b\f\u0010\bR\"\u0010\u0011\u001a\u00020\u00028\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u000e\u0010\u0004\u001a\u0004\b\u000f\u0010\u0006\"\u0004\b\u0010\u0010\b¨\u0006\u0016"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/utils/banner/BannerViewHolder3;", "Landroidx/recyclerview/widget/RecyclerView$ViewHolder;", "Landroid/widget/ImageView;", "c", "Landroid/widget/ImageView;", "getImageView3", "()Landroid/widget/ImageView;", "setImageView3", "(Landroid/widget/ImageView;)V", "imageView3", "a", "getImageView", "setImageView", "imageView", "b", "getImageView2", "setImageView2", "imageView2", "Landroid/view/View;", "view", "<init>", "(Landroid/view/View;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class BannerViewHolder3 extends RecyclerView.ViewHolder {

    /* renamed from: a, reason: from kotlin metadata */
    @NotNull
    public ImageView imageView;

    /* renamed from: b, reason: from kotlin metadata */
    @NotNull
    public ImageView imageView2;

    /* renamed from: c, reason: from kotlin metadata */
    @NotNull
    public ImageView imageView3;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public BannerViewHolder3(@NonNull @NotNull View view) {
        super(view);
        Intrinsics.checkNotNullParameter(view, "view");
        View findViewById = view.findViewById(R.id.image);
        Intrinsics.checkNotNullExpressionValue(findViewById, "view.findViewById<ImageView>(R.id.image)");
        this.imageView = (ImageView) findViewById;
        View findViewById2 = view.findViewById(R.id.image2);
        Intrinsics.checkNotNullExpressionValue(findViewById2, "view.findViewById<ImageView>(R.id.image2)");
        this.imageView2 = (ImageView) findViewById2;
        View findViewById3 = view.findViewById(R.id.image3);
        Intrinsics.checkNotNullExpressionValue(findViewById3, "view.findViewById<ImageView>(R.id.image3)");
        this.imageView3 = (ImageView) findViewById3;
    }
}
