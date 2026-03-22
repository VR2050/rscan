package com.jbzd.media.movecartoons.utils.banner;

import android.view.View;
import android.widget.ImageView;
import androidx.recyclerview.widget.RecyclerView;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010\t\u001a\u00020\b¢\u0006\u0004\b\n\u0010\u000bR\u0019\u0010\u0007\u001a\u00020\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\u0003\u0010\u0004\u001a\u0004\b\u0005\u0010\u0006¨\u0006\f"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/utils/banner/ImageHolder;", "Landroidx/recyclerview/widget/RecyclerView$ViewHolder;", "Landroid/widget/ImageView;", "a", "Landroid/widget/ImageView;", "getImageView", "()Landroid/widget/ImageView;", "imageView", "Landroid/view/View;", "view", "<init>", "(Landroid/view/View;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class ImageHolder extends RecyclerView.ViewHolder {

    /* renamed from: a, reason: from kotlin metadata */
    @NotNull
    public final ImageView imageView;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ImageHolder(@NotNull View view) {
        super(view);
        Intrinsics.checkNotNullParameter(view, "view");
        this.imageView = (ImageView) view;
    }
}
